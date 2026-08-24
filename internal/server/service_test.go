package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	toolkitlogger "github.com/acexy/golang-toolkit/logger"
	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	proxyregistry "github.com/acexy/portway/internal/proxy/registry"
	"github.com/acexy/portway/internal/session"
	"github.com/acexy/portway/internal/transport"
	"github.com/sirupsen/logrus"
)

func TestValidateGovernedProxiesAppliesTypePortAndDomainPermissions(t *testing.T) {
	service := &Service{
		configuration: newConfigurationManager(config.ServerConfig{
			GovernedClients: map[string]config.GovernedClientConfig{
				"customer-a": {
					ClientID: "customer-a",
					Permissions: config.GovernedPermissions{
						ProxyTypes: []protocol.ProxyType{
							protocol.ProxyTypeTCP,
							protocol.ProxyTypeHTTP,
						},
						TCP: config.ProxyPermission{
							RemotePortRanges: []config.PortRange{{Start: 20000, End: 20999}},
						},
						HTTP: config.HTTPPermission{
							PublicSchemes: []protocol.HTTPPublicScheme{
								protocol.HTTPPublicSchemeHTTPS,
							},
							Domains: []string{"*.customer-a.example.com"},
						},
						Limits: config.PermissionLimits{MaxProxies: 2},
					},
				},
			},
		}),
	}
	allowed := protocol.SyncProxies{
		Revision: 1,
		Proxies: []protocol.ProxyDeclaration{
			{Name: "ssh", Type: protocol.ProxyTypeTCP, RemotePort: 20022},
			{
				Name: "web", Type: protocol.ProxyTypeHTTP,
				Domain:        "app.customer-a.example.com",
				PublicSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTPS},
			},
		},
	}
	if result := service.validateGovernedProxies("customer-a", allowed); result != nil {
		t.Fatalf("allowed governed configuration was rejected: %+v", result)
	}

	disallowed := allowed
	disallowed.Proxies = append([]protocol.ProxyDeclaration(nil), allowed.Proxies...)
	disallowed.Proxies[0].RemotePort = 22022
	result := service.validateGovernedProxies("customer-a", disallowed)
	if result == nil || result.Error == nil ||
		result.Error.Code != protocol.ProxyErrorRemotePortNotAllowed {
		t.Fatalf("expected remote port rejection, got %+v", result)
	}

	disallowed = allowed
	disallowed.Proxies = append([]protocol.ProxyDeclaration(nil), allowed.Proxies...)
	disallowed.Proxies[1].PublicSchemes = []protocol.HTTPPublicScheme{
		protocol.HTTPPublicSchemeHTTP,
	}
	result = service.validateGovernedProxies("customer-a", disallowed)
	if result == nil || result.Error == nil ||
		result.Error.Code != protocol.ProxyErrorPublicSchemeNotAllowed {
		t.Fatalf("expected public scheme rejection, got %+v", result)
	}
}

func TestApplyConfigurationCandidateReplacesAuthenticationSnapshot(t *testing.T) {
	originalToken := "original-shared-token-with-at-least-32-random-bytes"
	replacementToken := "replacement-shared-token-with-at-least-32-random-bytes"
	original := config.DefaultServer()
	original.Authentication.SharedToken = &originalToken
	replacement := original
	replacement.Authentication.SharedToken = &replacementToken

	snapshot, err := config.BuildAuthenticationSnapshot(original)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		logger:              logging.New("test"),
		configuration:       newConfigurationManager(original),
		clientRegistry:      session.NewRegistry(),
		authenticationStore: authentication.NewStore(snapshot),
	}
	if err := service.applyConfigurationCandidate(replacement); err != nil {
		t.Fatal(err)
	}
	selector := authentication.Selector(replacementToken)
	record, exists := service.authenticationStore.Resolve(selector[:])
	if !exists || record.Context.Mode != authentication.ModeShared {
		t.Fatal("replacement authentication snapshot was not published")
	}
	oldSelector := authentication.Selector(originalToken)
	if _, exists := service.authenticationStore.Resolve(oldSelector[:]); exists {
		t.Fatal("previous authentication snapshot remained active")
	}
}

func TestApplyConfigurationCandidateReusesGeneratedTokenWhenSourceOmitsIt(t *testing.T) {
	generatedToken := "generated-shared-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.Authentication.SharedToken = &generatedToken
	current.SharedTokenGenerated = true
	candidate := config.DefaultServer()
	candidate.SourceDigest = "next-source-generation"

	snapshot, err := config.BuildAuthenticationSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	store := authentication.NewStore(snapshot)
	service := &Service{
		logger:              logging.New("test"),
		configuration:       newConfigurationManager(current),
		clientRegistry:      session.NewRegistry(),
		authenticationStore: store,
	}
	selector := authentication.Selector(generatedToken)
	previous, exists := store.Resolve(selector[:])
	if !exists {
		t.Fatal("generated authentication record is unavailable")
	}

	if err := service.applyConfigurationCandidate(candidate); err != nil {
		t.Fatal(err)
	}
	updated, exists := store.Resolve(selector[:])
	if !exists {
		t.Fatal("generated Token was replaced during an unchanged reload")
	}
	if updated.Context != previous.Context {
		t.Fatal("generated Token authentication generation changed during reload")
	}
}

func TestRevokedAuthenticationContextsSelectsChangedClient(t *testing.T) {
	governedToken := "governed-token-with-at-least-32-random-bytes"
	managedToken := "managed-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.GovernedClients = map[string]config.GovernedClientConfig{
		"governed": {
			ClientID: "governed",
			Token:    governedToken,
			Permissions: config.GovernedPermissions{
				ProxyTypes: []protocol.ProxyType{protocol.ProxyTypeTCP},
			},
		},
	}
	current.ManagedClients = map[string]config.ManagedClientConfig{
		"managed": {
			ClientID: "managed",
			Token:    managedToken,
			Configuration: config.ManagedConfiguration{
				Revision: 1,
			},
		},
	}
	candidate := current
	candidate.GovernedClients = map[string]config.GovernedClientConfig{
		"governed": current.GovernedClients["governed"],
	}
	changed := candidate.GovernedClients["governed"]
	changed.Permissions.Limits.MaxProxies = 1
	candidate.GovernedClients["governed"] = changed

	currentSnapshot, err := config.BuildAuthenticationSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	store := authentication.NewStore(currentSnapshot)
	candidateSnapshot, err := config.BuildAuthenticationSnapshot(candidate)
	if err != nil {
		t.Fatal(err)
	}
	revoked := revokedAuthenticationContexts(
		store.Load(),
		candidateSnapshot,
		current,
		candidate,
	)
	if len(revoked) != 1 ||
		revoked[0].Mode != authentication.ModeGoverned ||
		revoked[0].ClientID != "governed" {
		t.Fatalf("unexpected revoked contexts: %+v", revoked)
	}
}

func TestRevokedAuthenticationContextsRejectsModeMigration(t *testing.T) {
	token := "client-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.GovernedClients = map[string]config.GovernedClientConfig{
		"client-one": {
			ClientID: "client-one",
			Token:    token,
		},
	}
	candidate := config.DefaultServer()
	candidate.ManagedClients = map[string]config.ManagedClientConfig{
		"client-one": {
			ClientID: "client-one",
			Token:    token,
			Configuration: config.ManagedConfiguration{
				Revision: 1,
			},
		},
	}
	currentSnapshot, err := config.BuildAuthenticationSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	store := authentication.NewStore(currentSnapshot)
	candidateSnapshot, err := config.BuildAuthenticationSnapshot(candidate)
	if err != nil {
		t.Fatal(err)
	}
	revoked := revokedAuthenticationContexts(
		store.Load(),
		candidateSnapshot,
		current,
		candidate,
	)
	if len(revoked) != 1 ||
		revoked[0].Mode != authentication.ModeGoverned ||
		revoked[0].ClientID != "client-one" {
		t.Fatalf("mode migration did not revoke the old context: %+v", revoked)
	}
}

func TestAuthenticationTokensChangedIncludesRecordOwnership(t *testing.T) {
	token := "client-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.GovernedClients = map[string]config.GovernedClientConfig{
		"client-one": {ClientID: "client-one", Token: token},
	}

	unchanged := current
	unchanged.GovernedClients = map[string]config.GovernedClientConfig{
		"client-one": {ClientID: "client-one", Token: token},
	}
	if authenticationTokensChanged(current, unchanged) {
		t.Fatal("equivalent authentication records were reported as changed")
	}

	migrated := config.DefaultServer()
	migrated.ManagedClients = map[string]config.ManagedClientConfig{
		"client-one": {ClientID: "client-one", Token: token},
	}
	if !authenticationTokensChanged(current, migrated) {
		t.Fatal("authentication record mode migration was not reported as changed")
	}
}

func TestApplyConfigurationCandidateTokenChangeRevokesEverySession(t *testing.T) {
	sharedToken := "shared-token-with-at-least-32-random-bytes"
	governedToken := "governed-token-with-at-least-32-random-bytes"
	replacementGovernedToken := "replacement-governed-token-with-at-least-32-random-bytes"
	managedToken := "managed-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.Authentication.SharedToken = &sharedToken
	current.GovernedClients = map[string]config.GovernedClientConfig{
		"governed-client": {
			ClientID: "governed-client",
			Token:    governedToken,
		},
	}
	current.ManagedClients = map[string]config.ManagedClientConfig{
		"managed-client": {
			ClientID: "managed-client",
			Token:    managedToken,
			Configuration: config.ManagedConfiguration{
				Revision: 1,
			},
		},
	}
	candidate := current
	candidate.GovernedClients = map[string]config.GovernedClientConfig{
		"governed-client": {
			ClientID: "governed-client",
			Token:    replacementGovernedToken,
		},
	}

	snapshot, err := config.BuildAuthenticationSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	store := authentication.NewStore(snapshot)
	registry := session.NewRegistry()
	service := &Service{
		logger:              logging.New("test"),
		configuration:       newConfigurationManager(current),
		clientRegistry:      registry,
		authenticationStore: store,
		managed:             newManagedCoordinator(),
	}

	type registeredSession struct {
		clientID  string
		token     string
		sessionID string
		server    net.Conn
		client    net.Conn
		context   authentication.Context
	}
	sessions := []registeredSession{
		{clientID: "shared-instance", token: sharedToken, sessionID: "shared-session"},
		{clientID: "governed-client", token: governedToken, sessionID: "governed-session"},
		{clientID: "managed-client", token: managedToken, sessionID: "managed-session"},
	}
	for index := range sessions {
		selector := authentication.Selector(sessions[index].token)
		record, exists := store.Resolve(selector[:])
		if !exists {
			t.Fatalf("authentication record for %s is unavailable", sessions[index].clientID)
		}
		sessions[index].context = record.Context
		sessions[index].server, sessions[index].client = net.Pipe()
		_, _, _, registrationError := registry.RegisterAuthenticated(
			sessions[index].clientID,
			"",
			sessions[index].sessionID,
			sessions[index].server,
			time.Now(),
			record.Context,
		)
		if registrationError != nil {
			t.Fatalf("register %s: %v", sessions[index].clientID, registrationError)
		}
		if !registry.Activate(
			sessions[index].clientID,
			sessions[index].sessionID,
			time.Now(),
		) {
			t.Fatalf("activate %s", sessions[index].clientID)
		}
		defer sessions[index].server.Close()
		defer sessions[index].client.Close()
	}
	registry.Disconnect("managed-client", "managed-session", time.Now())

	if err := service.applyConfigurationCandidate(candidate); err != nil {
		t.Fatal(err)
	}
	if stats := registry.SnapshotStats(); stats != (session.Stats{}) {
		t.Fatalf("sessions remained after Token reload: %+v", stats)
	}
	for _, registered := range sessions {
		if store.IsCurrent(registered.context) {
			t.Fatalf("old authentication context for %s remained current", registered.clientID)
		}
		if accepted := serverTestHeartbeatAccepted(
			registry,
			registered.clientID,
			registered.sessionID,
			1,
			time.Now(),
		); accepted {
			t.Fatalf("session for %s remained registered", registered.clientID)
		}
		if err := registered.client.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
			if _, err := registered.client.Read(make([]byte, 1)); err == nil {
				t.Fatalf("control connection for %s remained open", registered.clientID)
			}
		}
	}
	replacementSelector := authentication.Selector(replacementGovernedToken)
	if _, exists := store.Resolve(replacementSelector[:]); !exists {
		t.Fatal("replacement Token was not published")
	}
}

func TestApplyConfigurationCandidateRevokesOnlyChangedGovernedSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	broker := link.NewBroker(ctx)
	defer broker.Close()
	proxyPort := uint16(reserveTCPAddress(t).Port)
	sharedToken := "shared-token-with-at-least-32-random-bytes"
	governedToken := "governed-token-with-at-least-32-random-bytes"
	managedToken := "managed-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.Authentication.SharedToken = &sharedToken
	current.GovernedClients = map[string]config.GovernedClientConfig{
		"governed-client": {
			ClientID: "governed-client",
			Token:    governedToken,
			Permissions: config.GovernedPermissions{
				ProxyTypes: []protocol.ProxyType{protocol.ProxyTypeTCP},
			},
		},
	}
	current.ManagedClients = map[string]config.ManagedClientConfig{
		"managed-client": {
			ClientID: "managed-client",
			Token:    managedToken,
			Configuration: config.ManagedConfiguration{
				Revision: 1,
			},
		},
	}
	candidate := current
	candidate.GovernedClients = map[string]config.GovernedClientConfig{
		"governed-client": current.GovernedClients["governed-client"],
	}
	changedGoverned := candidate.GovernedClients["governed-client"]
	changedGoverned.Permissions.Limits.MaxProxies = 1
	candidate.GovernedClients["governed-client"] = changedGoverned

	snapshot, err := config.BuildAuthenticationSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	store := authentication.NewStore(snapshot)
	registry := session.NewRegistry()
	service := &Service{
		logger:              logging.New("test"),
		configuration:       newConfigurationManager(current),
		clientRegistry:      registry,
		authenticationStore: store,
		linkBroker:          broker,
		managed:             newManagedCoordinator(),
	}
	service.proxyRegistry = proxyregistry.New(
		ctx,
		logging.New("test"),
		"127.0.0.1",
		broker,
		false,
		config.DefaultServer().HTTP,
	)
	defer service.proxyRegistry.Close()

	type registeredSession struct {
		clientID string
		token    string
		server   net.Conn
		client   net.Conn
	}
	sessions := []registeredSession{
		{clientID: "shared-instance", token: sharedToken},
		{clientID: "governed-client", token: governedToken},
		{clientID: "managed-client", token: managedToken},
	}
	for index := range sessions {
		selector := authentication.Selector(sessions[index].token)
		record, exists := store.Resolve(selector[:])
		if !exists {
			t.Fatalf("authentication record for %s is unavailable", sessions[index].clientID)
		}
		sessions[index].server, sessions[index].client = net.Pipe()
		_, _, _, registrationError := registry.RegisterAuthenticated(
			sessions[index].clientID,
			"",
			fmt.Sprintf("session-%d", index),
			sessions[index].server,
			time.Now(),
			record.Context,
		)
		if registrationError != nil {
			t.Fatalf("register %s: %v", sessions[index].clientID, registrationError)
		}
		if !registry.Activate(
			sessions[index].clientID,
			fmt.Sprintf("session-%d", index),
			time.Now(),
		) {
			t.Fatalf("activate %s", sessions[index].clientID)
		}
		service.proxyRegistry.AttachAuthenticated(
			sessions[index].clientID,
			fmt.Sprintf("session-%d", index),
			control.NewWriter(sessions[index].server),
			record.Context,
			0,
		)
		defer sessions[index].server.Close()
		defer sessions[index].client.Close()
	}
	result := service.proxyRegistry.Sync(
		"governed-client",
		"session-1",
		"request-one",
		protocol.SyncProxies{
			Revision: 1,
			Proxies: []protocol.ProxyDeclaration{{
				Name:       "governed-proxy",
				Type:       protocol.ProxyTypeTCP,
				RemotePort: proxyPort,
			}},
		},
	)
	if result.Status != protocol.ProxySyncStatusApplied {
		t.Fatalf("register governed proxy: %+v", result)
	}

	if err := service.applyConfigurationCandidate(candidate); err != nil {
		t.Fatal(err)
	}
	if serverTestHeartbeatAccepted(registry, "governed-client", "session-1", 1, time.Now()) {
		t.Fatal("changed governed session remained registered")
	}
	if !serverTestHeartbeatAccepted(registry, "shared-instance", "session-0", 1, time.Now()) {
		t.Fatal("unrelated shared session was revoked")
	}
	if !serverTestHeartbeatAccepted(registry, "managed-client", "session-2", 1, time.Now()) {
		t.Fatal("unrelated managed session was revoked")
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	if err != nil {
		t.Fatalf("revoked governed listener was not released: %v", err)
	}
	listener.Close()
}

func TestApplyConfigurationCandidateUpdatesSourceDigestWithoutGeneration(t *testing.T) {
	token := "shared-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.Authentication.SharedToken = &token
	current.SourceDigest = "old"
	current.Generation = 7
	candidate := current
	candidate.SourceDigest = "new"
	snapshot, err := config.BuildAuthenticationSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		logger:              logging.New("test"),
		configuration:       newConfigurationManager(current),
		clientRegistry:      session.NewRegistry(),
		authenticationStore: authentication.NewStore(snapshot),
	}
	if err := service.applyConfigurationCandidate(candidate); err != nil {
		t.Fatal(err)
	}
	updated := service.configuration.snapshot()
	if updated.SourceDigest != "new" || updated.Generation != 7 {
		t.Fatalf("unexpected metadata-only update: %+v", updated)
	}
}

func TestApplyConfigurationCandidateChangesLogLevelRepeatedly(t *testing.T) {
	token := "shared-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.Authentication.SharedToken = &token
	snapshot, err := config.BuildAuthenticationSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		logger:              logging.New("test"),
		configuration:       newConfigurationManager(current),
		clientRegistry:      session.NewRegistry(),
		authenticationStore: authentication.NewStore(snapshot),
		managed:             newManagedCoordinator(),
	}
	activeLogger := toolkitlogger.Logrus()
	originalLevel := activeLogger.GetLevel()
	t.Cleanup(func() {
		activeLogger.SetLevel(originalLevel)
	})

	for _, testCase := range []struct {
		configured config.LogLevel
		expected   logrus.Level
	}{
		{configured: config.LogLevelDebug, expected: logrus.DebugLevel},
		{configured: config.LogLevelTrace, expected: logrus.TraceLevel},
		{configured: config.LogLevelError, expected: logrus.ErrorLevel},
	} {
		candidate := service.configuration.snapshot()
		candidate.LogLevel = testCase.configured
		if err := service.applyConfigurationCandidate(candidate); err != nil {
			t.Fatalf("apply log level %q: %v", testCase.configured, err)
		}
		if service.configuration.snapshot().LogLevel != testCase.configured {
			t.Fatalf(
				"configuration log level was not updated to %q",
				testCase.configured,
			)
		}
		if activeLogger.GetLevel() != testCase.expected {
			t.Fatalf(
				"logger level = %s, want %s",
				activeLogger.GetLevel(),
				testCase.expected,
			)
		}
	}
}

func TestRejectedConfigurationCandidateKeepsLogLevel(t *testing.T) {
	token := "shared-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.Authentication.SharedToken = &token
	snapshot, err := config.BuildAuthenticationSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		logger:              logging.New("test"),
		configuration:       newConfigurationManager(current),
		clientRegistry:      session.NewRegistry(),
		authenticationStore: authentication.NewStore(snapshot),
	}
	activeLogger := toolkitlogger.Logrus()
	originalLevel := activeLogger.GetLevel()
	t.Cleanup(func() {
		activeLogger.SetLevel(originalLevel)
	})
	activeLogger.SetLevel(logrus.InfoLevel)

	candidate := current
	candidate.LogLevel = config.LogLevelTrace
	candidate.Transport.ListenAddress = "127.0.0.1:7001"
	if err := service.applyConfigurationCandidate(candidate); err == nil {
		t.Fatal("restart-required candidate was accepted")
	}
	if activeLogger.GetLevel() != logrus.InfoLevel {
		t.Fatalf("rejected candidate changed logger level to %s", activeLogger.GetLevel())
	}
	if service.configuration.snapshot().LogLevel != current.LogLevel {
		t.Fatal("rejected candidate changed configuration log level")
	}
}

func TestMapChangeCounts(t *testing.T) {
	current := map[string]int{"removed": 1, "changed": 1, "same": 1}
	candidate := map[string]int{"added": 1, "changed": 2, "same": 1}
	added, changed, removed := mapChangeCounts(current, candidate)
	if added != 1 || changed != 1 || removed != 1 {
		t.Fatalf(
			"change counts = added:%d changed:%d removed:%d",
			added,
			changed,
			removed,
		)
	}
}

func TestInboundAdmissionIsBoundedAndReusable(t *testing.T) {
	service := NewService(logging.New("test"), config.DefaultServer())
	releases := make([]func(), 0, maxUnaffiliatedInboundConnections)
	for range maxUnaffiliatedInboundConnections {
		release, admitted := service.acquireInboundAdmission()
		if !admitted {
			t.Fatal("inbound admission rejected before reaching its limit")
		}
		releases = append(releases, release)
	}
	if _, admitted := service.acquireInboundAdmission(); admitted {
		t.Fatal("inbound admission exceeded its hard limit")
	}
	releases[0]()
	releases[0]()
	release, admitted := service.acquireInboundAdmission()
	if !admitted {
		t.Fatal("released inbound admission capacity was not reusable")
	}
	release()
	for _, release := range releases[1:] {
		release()
	}
}

func TestSuspendClientPreservesProxyActivationAfterHeartbeatRecovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverConnection, clientConnection := net.Pipe()
	defer serverConnection.Close()
	defer clientConnection.Close()
	broker := link.NewBroker(ctx)
	defer broker.Close()
	clientRegistry := session.NewRegistry()
	service := &Service{clientRegistry: clientRegistry}
	service.proxyRegistry = proxyregistry.New(
		ctx,
		logging.New("test"),
		"127.0.0.1",
		broker,
		false,
		config.DefaultServer().HTTP,
	)
	defer service.proxyRegistry.Close()

	now := time.Now()
	clientRegistry.Register("client-one", "", "session-one", serverConnection, now)
	clientRegistry.Activate("client-one", "session-one", now)
	service.proxyRegistry.Attach("client-one", "session-one", control.NewWriter(serverConnection))
	service.proxyRegistry.Activate("client-one", "session-one")
	suspended, _ := clientRegistry.Sweep(
		now.Add(controlHeartbeatTimeout),
		controlHeartbeatTimeout,
		clientRecoveryWindow,
	)
	if len(suspended) != 1 {
		t.Fatalf("expected one suspended session, got %v", suspended)
	}
	heartbeatAccepted, reactivated := clientRegistry.Heartbeat(
		"client-one",
		"session-one",
		1,
		now.Add(controlHeartbeatTimeout+time.Millisecond),
	)
	if !heartbeatAccepted || !reactivated {
		t.Fatal("heartbeat did not reactivate the suspended session")
	}
	if service.suspendClient(suspended[0]) {
		t.Fatal("stale suspension was reported as applied")
	}
	if !service.proxyRegistry.Active("client-one", "session-one") {
		t.Fatal("stale suspension left the recovered proxy inactive")
	}
}

func serverTestHeartbeatAccepted(
	registry *session.Registry,
	clientID string,
	sessionID string,
	sequence uint64,
	now time.Time,
) bool {
	accepted, _ := registry.Heartbeat(clientID, sessionID, sequence, now)
	return accepted
}

func TestApplyConfigurationCandidateReportsRestartField(t *testing.T) {
	token := "shared-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.Authentication.SharedToken = &token
	candidate := current
	candidate.Transport.ListenAddress = "127.0.0.1:7001"
	snapshot, err := config.BuildAuthenticationSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		logger:              logging.New("test"),
		configuration:       newConfigurationManager(current),
		clientRegistry:      session.NewRegistry(),
		authenticationStore: authentication.NewStore(snapshot),
	}
	err = service.applyConfigurationCandidate(candidate)
	var restartError restartRequiredError
	if !errors.As(err, &restartError) ||
		restartError.field != "transport.listen_address" {
		t.Fatalf("expected precise restart field, got %v", err)
	}
}

func TestApplyConfigurationCandidateReloadsHTTPSCertificatePaths(t *testing.T) {
	token := "shared-token-with-at-least-32-random-bytes"
	certificateFile, keyFile := writeQUICServerCertificate(t)
	current := config.DefaultServer()
	current.Authentication.SharedToken = &token
	current.Tunnel.HTTPSListenAddress = "127.0.0.1:8443"
	current.HTTPS = config.HTTPSConfig{Certificates: []config.HTTPSCertificateConfig{{
		Domains:  []string{"localhost"},
		CertFile: certificateFile,
		KeyFile:  keyFile,
	}}}
	snapshot, err := config.BuildAuthenticationSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	certificateManager, err := newHTTPSCertificateManager(
		logging.New("test"),
		current.HTTPS,
	)
	if err != nil {
		t.Fatal(err)
	}
	initialSnapshot := certificateManager.snapshot.Load()
	service := &Service{
		logger:              logging.New("test"),
		configuration:       newConfigurationManager(current),
		clientRegistry:      session.NewRegistry(),
		authenticationStore: authentication.NewStore(snapshot),
		httpsCertificates:   certificateManager,
		managed:             newManagedCoordinator(),
	}

	replacementCertificateFile, replacementKeyFile := writeQUICServerCertificate(t)
	candidate := current
	candidate.HTTPS = config.HTTPSConfig{Certificates: []config.HTTPSCertificateConfig{{
		Domains:  []string{"localhost"},
		CertFile: replacementCertificateFile,
		KeyFile:  replacementKeyFile,
	}}}
	if err := service.applyConfigurationCandidate(candidate); err != nil {
		t.Fatalf("apply HTTPS certificate path update: %v", err)
	}
	if !reflect.DeepEqual(service.configuration.snapshot().HTTPS, candidate.HTTPS) {
		t.Fatal("HTTPS certificate paths were not published")
	}
	if certificateManager.snapshot.Load() == initialSnapshot {
		t.Fatal("HTTPS certificate path update did not replace the certificate")
	}
	activeSnapshot := certificateManager.snapshot.Load()
	invalidCandidate := candidate
	invalidCandidate.HTTPS.Certificates = append(
		[]config.HTTPSCertificateConfig(nil),
		candidate.HTTPS.Certificates...,
	)
	invalidCandidate.HTTPS.Certificates[0].KeyFile = replacementCertificateFile
	if err := service.applyConfigurationCandidate(invalidCandidate); err == nil {
		t.Fatal("invalid HTTPS certificate path update was accepted")
	}
	if !reflect.DeepEqual(service.configuration.snapshot().HTTPS, candidate.HTTPS) {
		t.Fatal("invalid HTTPS certificate update changed the configuration")
	}
	if certificateManager.snapshot.Load() != activeSnapshot {
		t.Fatal("invalid HTTPS certificate update replaced the active certificate")
	}
}

func TestApplyConfigurationCandidateRejectsExplicitSharedTokenRemoval(t *testing.T) {
	token := "shared-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.Authentication.SharedToken = &token
	empty := ""
	candidate := current
	candidate.Authentication.SharedToken = &empty
	snapshot, err := config.BuildAuthenticationSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		logger:              logging.New("test"),
		configuration:       newConfigurationManager(current),
		clientRegistry:      session.NewRegistry(),
		authenticationStore: authentication.NewStore(snapshot),
	}
	err = service.applyConfigurationCandidate(candidate)
	var restartError restartRequiredError
	if !errors.As(err, &restartError) ||
		restartError.field != "authentication.shared_token" {
		t.Fatalf("expected shared Token restart requirement, got %v", err)
	}
}

func TestManagedConfigurationRolloutCompletesOnActiveSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	broker := link.NewBroker(ctx)
	defer broker.Close()
	service := &Service{
		logger:         logging.New("test"),
		clientRegistry: session.NewRegistry(),
		linkBroker:     broker,
		managed:        newManagedCoordinator(),
	}
	service.proxyRegistry = proxyregistry.New(
		ctx,
		logging.New("test"),
		"127.0.0.1",
		broker,
		false,
		config.DefaultServer().HTTP,
	)
	defer service.proxyRegistry.Close()
	writer := control.NewWriter(serverConnection)
	service.proxyRegistry.AttachAuthenticated(
		"managed-client",
		"session-one",
		writer,
		authentication.Context{
			Mode:     authentication.ModeManaged,
			ClientID: "managed-client",
		},
		0,
	)
	service.registerManagedSession(
		"managed-client",
		"session-one",
		serverConnection,
		writer,
	)
	defer service.unregisterManagedSession("managed-client", "session-one")

	controlErrors := make(chan error, 1)
	go func() {
		_, err := service.serveControlMessages(
			serverConnection,
			"managed-client",
			"session-one",
			logging.New("test"),
			writer,
			[]protocol.Capability{protocol.CapabilityJSONControl},
			authentication.ModeManaged,
			false,
			nil,
		)
		controlErrors <- err
	}()
	clientErrors := make(chan error, 1)
	go func() {
		envelope, err := protocol.ReadControl(clientConnection)
		if err != nil {
			clientErrors <- err
			return
		}
		var preparation protocol.ManagedConfigPrepare
		if envelope.Type != protocol.MessageManagedConfigPrepare {
			clientErrors <- fmt.Errorf("unexpected message %s", envelope.Type)
			return
		}
		if err := protocol.DecodePayload(envelope, &preparation); err != nil {
			clientErrors <- err
			return
		}
		status := protocol.ManagedConfigStatus{
			Revision: preparation.Revision,
			Digest:   preparation.Digest,
		}
		if err := protocol.WriteControl(
			clientConnection,
			protocol.MessageManagedConfigPrepared,
			status,
		); err != nil {
			clientErrors <- err
			return
		}
		envelope, err = protocol.ReadControl(clientConnection)
		if err != nil {
			clientErrors <- err
			return
		}
		if envelope.Type != protocol.MessageManagedConfigActivate {
			clientErrors <- fmt.Errorf("unexpected message %s", envelope.Type)
			return
		}
		clientErrors <- protocol.WriteControl(
			clientConnection,
			protocol.MessageManagedConfigApplied,
			status,
		)
	}()

	err := service.rolloutManagedConfiguration(
		ctx,
		"managed-client",
		config.ManagedClientConfig{
			ClientID: "managed-client",
			Configuration: config.ManagedConfiguration{
				Revision: 2,
				Proxies:  []config.ProxyConfig{},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-clientErrors; err != nil {
		t.Fatal(err)
	}
	clientConnection.Close()
	<-controlErrors
}

func TestManagedConfigurationRolloutRejectsMismatchedPreparedStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	broker := link.NewBroker(ctx)
	defer broker.Close()
	service := &Service{
		logger:         logging.New("test"),
		clientRegistry: session.NewRegistry(),
		linkBroker:     broker,
		managed:        newManagedCoordinator(),
	}
	service.proxyRegistry = proxyregistry.New(
		ctx,
		logging.New("test"),
		"127.0.0.1",
		broker,
		false,
		config.DefaultServer().HTTP,
	)
	defer service.proxyRegistry.Close()
	writer := control.NewWriter(serverConnection)
	service.proxyRegistry.AttachAuthenticated(
		"managed-client",
		"session-one",
		writer,
		authentication.Context{
			Mode:     authentication.ModeManaged,
			ClientID: "managed-client",
		},
		0,
	)
	service.registerManagedSession(
		"managed-client",
		"session-one",
		serverConnection,
		writer,
	)
	defer service.unregisterManagedSession("managed-client", "session-one")

	controlErrors := make(chan error, 1)
	go func() {
		_, err := service.serveControlMessages(
			serverConnection,
			"managed-client",
			"session-one",
			logging.New("test"),
			writer,
			[]protocol.Capability{protocol.CapabilityJSONControl},
			authentication.ModeManaged,
			false,
			nil,
		)
		controlErrors <- err
	}()
	clientErrors := make(chan error, 1)
	go func() {
		envelope, err := protocol.ReadControl(clientConnection)
		if err != nil {
			clientErrors <- err
			return
		}
		var preparation protocol.ManagedConfigPrepare
		if err := protocol.DecodePayload(envelope, &preparation); err != nil {
			clientErrors <- err
			return
		}
		clientErrors <- protocol.WriteControl(
			clientConnection,
			protocol.MessageManagedConfigPrepared,
			protocol.ManagedConfigStatus{
				Revision: preparation.Revision + 1,
				Digest:   preparation.Digest,
			},
		)
	}()

	err := service.rolloutManagedConfiguration(
		ctx,
		"managed-client",
		config.ManagedClientConfig{
			ClientID: "managed-client",
			Configuration: config.ManagedConfiguration{
				Revision: 2,
			},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected mismatched prepared status rejection, got %v", err)
	}
	if err := <-clientErrors; err != nil {
		t.Fatal(err)
	}
	clientConnection.Close()
	<-controlErrors
}

func TestConfigurationReloadWaitsForAuthenticationRegistrationBarrier(t *testing.T) {
	token := "shared-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.Authentication.SharedToken = &token
	candidate := current
	candidate.LogLevel = config.LogLevelDebug
	snapshot, err := config.BuildAuthenticationSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		logger:              logging.New("test"),
		configuration:       newConfigurationManager(current),
		clientRegistry:      session.NewRegistry(),
		authenticationStore: authentication.NewStore(snapshot),
		managed:             newManagedCoordinator(),
	}

	service.authenticationBarrier.RLock()
	results := make(chan error, 1)
	go func() {
		results <- service.applyConfigurationCandidate(candidate)
	}()
	select {
	case err := <-results:
		service.authenticationBarrier.RUnlock()
		t.Fatalf("reload crossed the authentication registration barrier: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	service.authenticationBarrier.RUnlock()
	select {
	case err := <-results:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("reload did not continue after registration barrier release")
	}
}

func TestManagedConfigurationRevisionMustIncrease(t *testing.T) {
	token := "managed-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.ManagedClients = map[string]config.ManagedClientConfig{
		"managed-client": {
			ClientID: "managed-client",
			Token:    token,
			Configuration: config.ManagedConfiguration{
				Revision: 2,
				Proxies:  []config.ProxyConfig{},
			},
		},
	}
	candidate := current
	candidate.ManagedClients = map[string]config.ManagedClientConfig{
		"managed-client": {
			ClientID: "managed-client",
			Token:    token,
			Configuration: config.ManagedConfiguration{
				Revision: 2,
				Proxies: []config.ProxyConfig{{
					Name:       "ssh",
					Type:       "tcp",
					LocalIP:    "127.0.0.1",
					LocalPort:  22,
					RemotePort: 22022,
				}},
			},
		},
	}
	if err := validateManagedRevisionTransitions(current, candidate); err == nil {
		t.Fatal("managed configuration changed without increasing revision")
	}
}

type testStream struct {
	net.Conn
}

func (stream testStream) CloseWrite() error {
	return stream.Close()
}

func TestHandleConnectionRejectsInvalidClientIdentification(t *testing.T) {
	t.Parallel()

	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()

	service := &Service{}
	results := make(chan error, 1)
	go func() {
		results <- service.handleConnection(context.Background(), transport.Inbound{
			Stream:        testStream{Conn: serverConnection},
			Role:          protocol.RoleControl,
			RemoteAddress: "pipe",
		})
	}()

	envelope, err := protocol.ReadControl(clientConnection)
	if err != nil {
		t.Fatalf("read server identification: %v", err)
	}
	if envelope.Type != protocol.MessageServerIdentification {
		t.Fatalf("unexpected response type: %s", envelope.Type)
	}
	if err := protocol.WriteControl(
		clientConnection,
		protocol.MessageClientIdentification,
		protocol.ClientIdentification{
			Product:  protocol.ProductClient,
			Version:  "v0.0.1",
			OS:       protocol.OperatingSystemDarwin,
			Arch:     protocol.ArchitectureARM64,
			Hostname: "invalid\nhostname",
		},
	); err != nil {
		t.Fatalf("write client identification: %v", err)
	}

	err = <-results
	if err == nil || !strings.Contains(err.Error(), "control characters") {
		t.Fatalf("unexpected identification validation error: %v", err)
	}
}

func TestHandleConnectionRejectsAuthenticatedClientIDMismatchBeforeRegistration(t *testing.T) {
	t.Parallel()

	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()

	service := &Service{}
	results := make(chan error, 1)
	go func() {
		results <- service.handleConnection(context.Background(), transport.Inbound{
			Stream: testStream{Conn: serverConnection},
			Role:   protocol.RoleControl,
			Authentication: authentication.Context{
				Mode:     authentication.ModeManaged,
				ClientID: "managed-client",
			},
			RemoteAddress: "pipe",
		})
	}()

	if _, err := protocol.ReadControl(clientConnection); err != nil {
		t.Fatalf("read server identification: %v", err)
	}
	if err := protocol.WriteControl(
		clientConnection,
		protocol.MessageClientIdentification,
		validTestClientIdentification(),
	); err != nil {
		t.Fatalf("write client identification: %v", err)
	}
	if err := protocol.WriteControl(
		clientConnection,
		protocol.MessageClientHello,
		protocol.ClientHello{
			ClientID:     "different-client",
			Capabilities: []protocol.Capability{protocol.CapabilityJSONControl},
		},
	); err != nil {
		t.Fatalf("write client hello: %v", err)
	}
	envelope, err := protocol.ReadControl(clientConnection)
	if err != nil {
		t.Fatalf("read session error: %v", err)
	}
	var sessionError protocol.SessionError
	if envelope.Type != protocol.MessageSessionError {
		t.Fatalf("unexpected response type: %s", envelope.Type)
	}
	if err := protocol.DecodePayload(envelope, &sessionError); err != nil {
		t.Fatalf("decode session error: %v", err)
	}
	if sessionError.Code != protocol.SessionErrorAuthenticationFailed ||
		sessionError.Message != transport.ErrAuthentication.Error() ||
		sessionError.Retryable {
		t.Fatalf("unexpected session error: %+v", sessionError)
	}
	if err := <-results; !errors.Is(err, transport.ErrAuthentication) {
		t.Fatalf("unexpected handler result: %v", err)
	}
}

func TestManagedInitializationFailureRemovesNewSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	token := "managed-token-with-at-least-32-random-bytes"
	configuration := config.DefaultServer()
	configuration.ManagedClients = map[string]config.ManagedClientConfig{
		"managed-client": {
			ClientID: "managed-client",
			Token:    token,
			Configuration: config.ManagedConfiguration{
				Revision: 1,
			},
		},
	}
	snapshot, err := config.BuildAuthenticationSnapshot(configuration)
	if err != nil {
		t.Fatal(err)
	}
	store := authentication.NewStore(snapshot)
	selector := authentication.Selector(token)
	record, exists := store.Resolve(selector[:])
	if !exists {
		t.Fatal("managed authentication record was not indexed")
	}
	broker := link.NewBroker(ctx)
	defer broker.Close()
	service := &Service{
		logger:              logging.New("test"),
		configuration:       newConfigurationManager(configuration),
		clientRegistry:      session.NewRegistry(),
		linkBroker:          broker,
		authenticationStore: store,
		managed:             newManagedCoordinator(),
	}
	service.proxyRegistry = proxyregistry.New(
		ctx,
		logging.New("test"),
		"127.0.0.1",
		broker,
		false,
		configuration.HTTP,
	)
	defer service.proxyRegistry.Close()

	clientConnection, serverConnection := net.Pipe()
	results := make(chan error, 1)
	go func() {
		results <- service.handleConnection(ctx, transport.Inbound{
			Stream:         testStream{Conn: serverConnection},
			Role:           protocol.RoleControl,
			Authentication: record.Context,
			RemoteAddress:  "pipe",
		})
	}()
	if _, err := protocol.ReadControl(clientConnection); err != nil {
		t.Fatalf("read server identification: %v", err)
	}
	if err := protocol.WriteControl(
		clientConnection,
		protocol.MessageClientIdentification,
		validTestClientIdentification(),
	); err != nil {
		t.Fatalf("write client identification: %v", err)
	}
	if err := protocol.WriteControl(
		clientConnection,
		protocol.MessageClientHello,
		protocol.ClientHello{
			ClientID: "managed-client",
			Capabilities: []protocol.Capability{
				protocol.CapabilityTCP,
				protocol.CapabilityUDP,
				protocol.CapabilityHTTP,
				protocol.CapabilityJSONControl,
			},
		},
	); err != nil {
		t.Fatalf("write client hello: %v", err)
	}
	if _, err := protocol.ReadControl(clientConnection); err != nil {
		t.Fatalf("read server hello: %v; handler: %v", err, <-results)
	}
	clientConnection.Close()
	<-results

	_, created, _, sessionError := service.clientRegistry.RegisterAuthenticated(
		"managed-client",
		"",
		"replacement-session",
		serverConnection,
		time.Now(),
		record.Context,
	)
	if sessionError != nil || !created {
		t.Fatalf(
			"failed managed initialization retained its session: created=%t error=%+v",
			created,
			sessionError,
		)
	}
	service.clientRegistry.Remove("managed-client", "replacement-session")
}

func validTestClientIdentification() protocol.ClientIdentification {
	return protocol.ClientIdentification{
		Product:  protocol.ProductClient,
		Version:  "v0.0.1",
		OS:       protocol.OperatingSystemDarwin,
		Arch:     protocol.ArchitectureARM64,
		Hostname: "test-client",
	}
}

func TestServeControlMessagesAcceptsGracefulClose(t *testing.T) {
	t.Parallel()

	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()
	defer serverConnection.Close()

	type serverResult struct {
		gracefullyClosed bool
		err              error
	}
	results := make(chan serverResult, 1)
	service := &Service{}
	writer := control.NewWriter(serverConnection)
	go func() {
		gracefullyClosed, err := service.serveControlMessages(
			serverConnection,
			"client-one",
			"session-one",
			logging.New("test").WithFields(map[string]any{
				"client_id":  "client-one",
				"session_id": "session-one",
			}),
			writer,
			[]protocol.Capability{protocol.CapabilityTCP, protocol.CapabilityJSONControl},
			authentication.ModeShared,
			false,
			nil,
		)
		results <- serverResult{gracefullyClosed: gracefullyClosed, err: err}
	}()

	if err := protocol.WriteControl(
		clientConnection,
		protocol.MessageCloseSession,
		protocol.CloseSession{
			SessionID: "session-one",
			Reason:    protocol.CloseReasonClientShutdown,
		},
	); err != nil {
		t.Fatalf("write close session: %v", err)
	}

	envelope, err := protocol.ReadControl(clientConnection)
	if err != nil {
		t.Fatalf("read close acknowledgment: %v", err)
	}
	if envelope.Type != protocol.MessageCloseAck {
		t.Fatalf("unexpected response type: %s", envelope.Type)
	}
	var acknowledgment protocol.CloseAck
	if err := protocol.DecodePayload(envelope, &acknowledgment); err != nil {
		t.Fatalf("decode close acknowledgment: %v", err)
	}
	if acknowledgment.SessionID != "session-one" {
		t.Fatalf("unexpected acknowledged session ID %q", acknowledgment.SessionID)
	}

	result := <-results
	if result.err != nil || !result.gracefullyClosed {
		t.Fatalf(
			"graceful close failed: closed=%t error=%v",
			result.gracefullyClosed,
			result.err,
		)
	}
}

func TestServeControlMessagesRequiresInitialProxySynchronization(t *testing.T) {
	t.Parallel()

	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()
	defer serverConnection.Close()

	results := make(chan error, 1)
	service := &Service{}
	go func() {
		_, err := service.serveControlMessages(
			serverConnection,
			"client-one",
			"session-one",
			logging.New("test"),
			control.NewWriter(serverConnection),
			[]protocol.Capability{protocol.CapabilityTCP, protocol.CapabilityJSONControl},
			authentication.ModeShared,
			true,
			nil,
		)
		results <- err
	}()

	if err := protocol.WriteControl(
		clientConnection,
		protocol.MessagePing,
		protocol.Heartbeat{Sequence: 1},
	); err != nil {
		t.Fatal(err)
	}
	if err := <-results; err == nil ||
		!strings.Contains(err.Error(), "expected initial sync_proxies") {
		t.Fatalf("unexpected initial message error: %v", err)
	}
}

func TestServeControlMessagesRejectsTCPMessageWithoutCapability(t *testing.T) {
	t.Parallel()

	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()
	defer serverConnection.Close()

	results := make(chan error, 1)
	service := &Service{}
	go func() {
		_, err := service.serveControlMessages(
			serverConnection,
			"client-one",
			"session-one",
			logging.New("test"),
			control.NewWriter(serverConnection),
			[]protocol.Capability{protocol.CapabilityJSONControl},
			authentication.ModeShared,
			false,
			nil,
		)
		results <- err
	}()

	if err := protocol.WriteControlWithRequestID(
		clientConnection,
		protocol.MessageSyncProxies,
		"request-one",
		protocol.SyncProxies{
			Revision: 1,
			Proxies: []protocol.ProxyDeclaration{
				{Name: "web", Type: protocol.ProxyTypeTCP, RemotePort: 8080},
			},
		},
	); err != nil {
		t.Fatalf("write proxy synchronization: %v", err)
	}

	err := <-results
	if err == nil || err.Error() != "tcp proxy registration requires a negotiated capability" {
		t.Fatalf("unexpected capability validation error: %v", err)
	}
}
