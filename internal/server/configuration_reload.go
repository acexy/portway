package server

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	proxyregistry "github.com/acexy/portway/internal/proxy/registry"
	"github.com/acexy/portway/internal/session"
)

func (s *Service) watchConfiguration(ctx context.Context) {
	sourcePath := s.configuration.snapshot().SourcePath
	if sourcePath == "" {
		return
	}
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	lastError := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		candidate, err := config.LoadServer(sourcePath, false)
		if err == nil {
			err = s.applyConfigurationCandidateContext(ctx, candidate)
		}
		if err != nil {
			if err.Error() != lastError {
				fields := map[string]any{
					"event":       "config_reload_failed",
					"error_code":  reloadErrorCode(err),
					"generation":  s.currentConfigurationGeneration(),
					"config_file": sourcePath,
				}
				var restartError restartRequiredError
				if errors.As(err, &restartError) {
					fields["field"] = restartError.field
				}
				s.logger.WithComponent("config_reload").WithFields(fields).Warn(
					"configuration reload failed; previous snapshot remains active",
					err,
				)
				lastError = err.Error()
			}
			continue
		}
		if lastError != "" {
			s.logger.WithComponent("config_reload").InfoWithFields(
				"configuration reload recovered",
				map[string]any{
					"event":       "config_reload_recovered",
					"config_file": sourcePath,
				},
			)
			lastError = ""
		}
	}
}

func (s *Service) watchHTTPSCertificate(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.httpsCertificates.reloadCurrent()
		}
	}
}

func (s *Service) applyConfigurationCandidate(candidate config.ServerConfig) error {
	return s.applyConfigurationCandidateContext(context.Background(), candidate)
}

func (s *Service) applyConfigurationCandidateContext(
	ctx context.Context,
	candidate config.ServerConfig,
) error {
	s.authenticationBarrier.Lock()
	barrierHeld := true
	defer func() {
		if barrierHeld {
			s.authenticationBarrier.Unlock()
		}
	}()

	current := s.configuration.snapshot()
	if err := config.ValidateForwardConfiguration(candidate); err != nil {
		return err
	}

	if serverTokenRequiresGeneration(candidate) &&
		current.Authentication.SharedToken != nil {
		if !current.SharedTokenGenerated {
			return restartRequiredError{field: "authentication.shared_token"}
		}
		sharedToken := *current.Authentication.SharedToken
		candidate.Authentication.SharedToken = &sharedToken
		candidate.SharedTokenGenerated = true
	}
	if _, _, err := config.EnsureServerToken(&candidate); err != nil {
		return err
	}
	if !reflect.DeepEqual(candidate.Transport, current.Transport) {
		return restartRequiredError{
			field: changedYAMLField("transport", current.Transport, candidate.Transport),
		}
	}
	if candidate.Proxies.BindIP != current.Proxies.BindIP {
		return restartRequiredError{
			field: "proxies.bind_ip",
		}
	}
	if candidate.Proxies.HTTP.ListenAddress != current.Proxies.HTTP.ListenAddress {
		return restartRequiredError{field: "proxies.http.listen_address"}
	}
	if candidate.Proxies.HTTPS.ListenAddress != current.Proxies.HTTPS.ListenAddress {
		return restartRequiredError{field: "proxies.https.listen_address"}
	}
	if !reflect.DeepEqual(candidate.Proxies.HTTP.HTTPConfig, current.Proxies.HTTP.HTTPConfig) {
		return restartRequiredError{
			field: changedYAMLField(
				"proxies.http",
				current.Proxies.HTTP.HTTPConfig,
				candidate.Proxies.HTTP.HTTPConfig,
			),
		}
	}
	httpsChanged := !reflect.DeepEqual(
		candidate.Proxies.HTTPS.Certificates,
		current.Proxies.HTTPS.Certificates,
	)
	var candidateHTTPSCertificates *httpsCertificateSnapshot
	var candidateHTTPSDigest string
	if httpsChanged {
		if s.httpsCertificates == nil {
			return restartRequiredError{
				field: "proxies.https.certificates",
			}
		}
		var err error
		candidateHTTPSCertificates, candidateHTTPSDigest, err = loadHTTPSCertificates(candidate.Proxies.HTTPS)
		if err != nil {
			return fmt.Errorf("reload HTTPS certificate: %w", err)
		}
	}
	if !reflect.DeepEqual(candidate.Proxies.UDP, current.Proxies.UDP) {
		return restartRequiredError{
			field: changedYAMLField("proxies.udp", current.Proxies.UDP, candidate.Proxies.UDP),
		}
	}
	if !reflect.DeepEqual(candidate.Security, current.Security) {
		return restartRequiredError{
			field: changedYAMLField("security", current.Security, candidate.Security),
		}
	}
	if !reflect.DeepEqual(candidate.Operations, current.Operations) {
		return restartRequiredError{
			field: changedYAMLField("operations", current.Operations, candidate.Operations),
		}
	}
	if err := validateManagedRevisionTransitions(current, candidate); err != nil {
		return err
	}
	if reflect.DeepEqual(candidate.Authentication, current.Authentication) &&
		reflect.DeepEqual(candidate.GovernedClients, current.GovernedClients) &&
		reflect.DeepEqual(candidate.ManagedClients, current.ManagedClients) &&
		reflect.DeepEqual(candidate.Forwards, current.Forwards) &&
		!httpsChanged &&
		candidate.LogLevel == current.LogLevel {
		s.configuration.updateSourceDigest(candidate.SourceDigest)
		return nil
	}
	snapshot, err := config.BuildAuthenticationSnapshot(candidate)
	if err != nil {
		return err
	}
	authenticationChanged :=
		!reflect.DeepEqual(candidate.Authentication, current.Authentication) ||
			!reflect.DeepEqual(candidate.GovernedClients, current.GovernedClients) ||
			!reflect.DeepEqual(candidate.ManagedClients, current.ManagedClients)
	tokensChanged := authenticationTokensChanged(current, candidate)

	currentAuthenticationSnapshot := s.authenticationStore.Load()
	var revokedContexts []authentication.Context
	if tokensChanged {
		// A Token generation is a deployment-wide authentication boundary. Rotate
		// every existing context so active and recoverable clients must all prove
		// their credentials again against the newly published snapshot.
		revokedContexts = currentAuthenticationSnapshot.Contexts()
	} else {
		revokedContexts = revokedAuthenticationContexts(
			currentAuthenticationSnapshot,
			snapshot,
			current,
			candidate,
		)
	}
	managedChanges := changedManagedClients(current, candidate)
	if tokensChanged {
		// Disconnected Managed clients receive the latest desired configuration
		// during their next authenticated session instead of an online rollout.
		managedChanges = []string{}
	}
	governedAdded, governedChanged, governedRemoved := mapChangeCounts(
		current.GovernedClients,
		candidate.GovernedClients,
	)
	managedAdded, managedChanged, managedRemoved := mapChangeCounts(
		current.ManagedClients,
		candidate.ManagedClients,
	)
	var reservationTransaction *proxyregistry.ManagedReservationTransaction
	if s.proxyRegistry != nil {
		reservationTransaction, err = s.proxyRegistry.BeginManagedReservationUpdate(
			candidate.ManagedClients,
		)
		if err != nil {
			return fmt.Errorf("validate managed reservations: %w", err)
		}
		defer reservationTransaction.Rollback()
	}
	// Change only the level of the initialized logger after every fallible
	// candidate validation has succeeded. EnableConsole is startup-only and the
	// underlying logger deliberately panics when initialized more than once.
	if candidate.LogLevel != current.LogLevel {
		if err := logging.SetConsoleLevel(candidate.LogLevel); err != nil {
			return fmt.Errorf("apply log level: %w", err)
		}
	}
	candidate.Generation = current.Generation + 1

	if httpsChanged {
		s.httpsCertificates.publish(
			candidate.Proxies.HTTPS,
			candidateHTTPSCertificates,
			candidateHTTPSDigest,
		)
	}
	s.configuration.publish(candidate)
	s.authenticationStore.ReplaceRevoking(snapshot, revokedContexts)
	if reservationTransaction != nil {
		reservationTransaction.Commit()
	}

	var revokedSessions []session.ExpiredClient
	cleanupCallbacks := make([]func(), 0)
	if authenticationChanged {
		revokedSessions = s.clientRegistry.RevokeAuthentication(revokedContexts)
		if s.proxyRegistry != nil {
			for _, revoked := range revokedSessions {
				cleanupCallbacks = append(
					cleanupCallbacks,
					s.proxyRegistry.Detach(revoked.ClientID, revoked.SessionID),
				)
			}
		}
	}
	s.authenticationBarrier.Unlock()
	barrierHeld = false

	if s.transportServer != nil {
		s.transportServer.RevokeAuthentication(revokedContexts)
	}
	for _, cleanup := range cleanupCallbacks {
		cleanup()
	}
	for _, revoked := range revokedSessions {
		if s.forwardRegistry != nil {
			s.forwardRegistry.Remove(revoked.ClientID, revoked.SessionID)
		}
		if revoked.Connection != nil {
			_ = revoked.Connection.Close()
		}
	}
	if s.forwardRegistry != nil &&
		(!reflect.DeepEqual(current.Forwards, candidate.Forwards) ||
			!reflect.DeepEqual(current.GovernedClients, candidate.GovernedClients) ||
			!reflect.DeepEqual(current.ManagedClients, candidate.ManagedClients)) {
		s.forwardRegistry.ApplyPolicy(
			candidate.Generation,
			func(context authentication.Context, declaration protocol.ForwardDeclaration) bool {
				return forwardPolicyChanged(current, candidate, context, declaration)
			},
		)
	}
	s.rolloutManagedConfigurations(ctx, managedChanges, candidate)
	s.logger.WithComponent("config_reload").InfoWithFields(
		"configuration reload applied",
		map[string]any{
			"event":                     "config_reload_applied",
			"config_file":               candidate.SourcePath,
			"governed_clients_path":     candidate.Authentication.GovernedClientsPath,
			"managed_clients_path":      candidate.Authentication.ManagedClientsPath,
			"old_generation":            current.Generation,
			"new_generation":            candidate.Generation,
			"log_level_changed":         candidate.LogLevel != current.LogLevel,
			"https_certificate_changed": httpsChanged,
			"shared_authentication_changed": !reflect.DeepEqual(
				candidate.Authentication.SharedToken,
				current.Authentication.SharedToken,
			),
			"governed_added":           governedAdded,
			"governed_changed":         governedChanged,
			"governed_removed":         governedRemoved,
			"managed_added":            managedAdded,
			"managed_changed":          managedChanged,
			"managed_removed":          managedRemoved,
			"managed_rollouts":         len(managedChanges),
			"tokens_changed":           tokensChanged,
			"all_clients_disconnected": tokensChanged,
			"revoked_authentications":  len(revokedContexts),
			"revoked_sessions":         len(revokedSessions),
		},
	)
	return nil
}

func authenticationTokensChanged(
	current config.ServerConfig,
	candidate config.ServerConfig,
) bool {
	return !reflect.DeepEqual(
		authenticationTokenRecords(current),
		authenticationTokenRecords(candidate),
	)
}

func serverTokenRequiresGeneration(configuration config.ServerConfig) bool {
	if configuration.Authentication.SharedToken != nil {
		return *configuration.Authentication.SharedToken == ""
	}
	return configuration.Authentication.GovernedClientsPath == "" &&
		configuration.Authentication.ManagedClientsPath == ""
}

func authenticationTokenRecords(configuration config.ServerConfig) map[string]string {
	records := make(map[string]string,
		1+len(configuration.GovernedClients)+len(configuration.ManagedClients),
	)
	if configuration.Authentication.SharedToken != nil {
		records[string(authentication.ModeShared)] = *configuration.Authentication.SharedToken
	}
	for _, client := range configuration.GovernedClients {
		records[string(authentication.ModeGoverned)+":"+client.Authentication.ClientID] = client.Authentication.Token
	}
	for _, client := range configuration.ManagedClients {
		records[string(authentication.ModeManaged)+":"+client.Authentication.ClientID] = client.Authentication.Token
	}
	return records
}

func (s *Service) rolloutManagedConfigurations(
	ctx context.Context,
	clientIDs []string,
	candidate config.ServerConfig,
) {
	rolloutContext, cancel := context.WithTimeout(ctx, managedRolloutTimeout)
	defer cancel()
	var waitGroup sync.WaitGroup
	for _, clientID := range clientIDs {
		managed := s.managed.get(clientID)
		if managed == nil {
			continue
		}
		waitGroup.Go(func() {
			if err := s.rolloutManagedConfiguration(
				rolloutContext,
				clientID,
				candidate.ManagedClients[clientID],
			); err != nil {
				_ = managed.connection.Close()
				s.logger.WithComponent("config_reload").WithFields(map[string]any{
					"event":      "managed_config_rollout_failed",
					"client_id":  clientID,
					"generation": candidate.Generation,
				}).Error("managed configuration rollout failed", err)
			}
		})
	}
	waitGroup.Wait()
}

func validateManagedRevisionTransitions(
	current config.ServerConfig,
	candidate config.ServerConfig,
) error {
	for clientID, next := range candidate.ManagedClients {
		previous, exists := current.ManagedClients[clientID]
		if !exists || previous.Authentication.Token != next.Authentication.Token ||
			reflect.DeepEqual(previous.Configuration, next.Configuration) {
			continue
		}
		if next.Configuration.Revision <= previous.Configuration.Revision {
			return fmt.Errorf(
				"managed client %q configuration.revision must increase from %d",
				clientID,
				previous.Configuration.Revision,
			)
		}
	}
	return nil
}

func (s *Service) currentConfigurationGeneration() uint64 {
	return s.configuration.snapshot().Generation
}

func reloadErrorCode(err error) string {
	var restartError restartRequiredError
	if errors.As(err, &restartError) {
		return "restart_required"
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "changed while loading"):
		return "configuration_generation_changed"
	case strings.Contains(message, "globally unique"):
		return "duplicate_authentication_token"
	case strings.Contains(message, "decode configuration"):
		return "invalid_yaml"
	case strings.Contains(message, "exceeds"):
		return "configuration_limit_exceeded"
	case strings.Contains(message, "authentication directory"):
		return "authentication_directory_invalid"
	case strings.Contains(message, "HTTPS certificate") ||
		strings.Contains(message, "HTTPS private key"):
		return "https_certificate_invalid"
	default:
		return "invalid_configuration"
	}
}

func changedYAMLField(prefix string, current any, candidate any) string {
	return changedYAMLValue(prefix, reflect.ValueOf(current), reflect.ValueOf(candidate))
}

func changedYAMLValue(prefix string, current reflect.Value, candidate reflect.Value) string {
	if reflect.DeepEqual(current.Interface(), candidate.Interface()) {
		return ""
	}
	if current.Kind() != reflect.Struct {
		return prefix
	}
	valueType := current.Type()
	for index := range current.NumField() {
		if reflect.DeepEqual(current.Field(index).Interface(), candidate.Field(index).Interface()) {
			continue
		}
		name := strings.Split(valueType.Field(index).Tag.Get("yaml"), ",")[0]
		if name == "" || name == "-" {
			name = valueType.Field(index).Name
		}
		field := name
		if prefix != "" {
			field = prefix + "." + name
		}
		return changedYAMLValue(field, current.Field(index), candidate.Field(index))
	}
	return prefix
}

func revokedAuthenticationContexts(
	currentSnapshot *authentication.Snapshot,
	candidateSnapshot *authentication.Snapshot,
	current config.ServerConfig,
	candidate config.ServerConfig,
) []authentication.Context {
	contexts := currentSnapshot.Contexts()
	revoked := coll.SliceFilter(contexts, func(context authentication.Context) bool {
		if !candidateSnapshot.ContainsRecord(context) {
			return true
		}
		switch context.Mode {
		case authentication.ModeGoverned:
			if !reflect.DeepEqual(
				current.GovernedClients[context.ClientID],
				candidate.GovernedClients[context.ClientID],
			) {
				return true
			}
		case authentication.ModeManaged:
			// Managed configuration changes use the online rollout state
			// machine. Token, identity, or mode changes are handled above by
			// ContainsRecord and still revoke the old authentication record.
		}
		return false
	})
	if revoked == nil {
		return []authentication.Context{}
	}
	return revoked
}

func changedManagedClients(
	current config.ServerConfig,
	candidate config.ServerConfig,
) []string {
	changed := coll.MapFilterToSlice(candidate.ManagedClients, func(clientID string, next config.ManagedClientConfig) (string, bool) {
		previous, exists := current.ManagedClients[clientID]
		if !exists || previous.Authentication.Token != next.Authentication.Token {
			return "", false
		}
		return clientID, !reflect.DeepEqual(previous.Configuration, next.Configuration)
	})
	if changed == nil {
		return []string{}
	}
	sort.Strings(changed)
	return changed
}

func mapChangeCounts[T any](current map[string]T, candidate map[string]T) (
	added int,
	changed int,
	removed int,
) {
	for key, next := range candidate {
		previous, exists := current[key]
		if !exists {
			added++
			continue
		}
		if !reflect.DeepEqual(previous, next) {
			changed++
		}
	}
	for key := range current {
		if _, exists := candidate[key]; !exists {
			removed++
		}
	}
	return added, changed, removed
}
