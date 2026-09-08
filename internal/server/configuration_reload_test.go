package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
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
	"github.com/sirupsen/logrus"
)

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
			Authentication: config.ClientAuthenticationConfig{ClientID: "governed", Token: governedToken},
			Permissions: config.GovernedPermissions{
				Proxies: config.GovernedProxyPermissions{
					TCP: &config.ProxyPermission{}, Limits: config.DefaultProxyPermissionLimits(),
				},
				Forwards: config.GovernedForwardPermissions{Limits: config.DefaultForwardPermissionLimits()},
			},
		},
	}
	current.ManagedClients = map[string]config.ManagedClientConfig{
		"managed": {
			Authentication: config.ClientAuthenticationConfig{ClientID: "managed", Token: managedToken},
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
	changed.Permissions.Proxies.Limits.MaxTotal = 1
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
			Authentication: config.ClientAuthenticationConfig{ClientID: "client-one", Token: token},
		},
	}
	candidate := config.DefaultServer()
	candidate.ManagedClients = map[string]config.ManagedClientConfig{
		"client-one": {
			Authentication: config.ClientAuthenticationConfig{ClientID: "client-one", Token: token},
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

func TestRevokedAuthenticationContextsScopesTokenRotationToRecord(t *testing.T) {
	sharedToken := "shared-token-with-at-least-32-random-bytes"
	governedToken := "governed-token-with-at-least-32-random-bytes"
	managedToken := "managed-token-with-at-least-32-random-bytes"
	base := func() config.ServerConfig {
		configuration := config.DefaultServer()
		configuration.Authentication.SharedToken = &sharedToken
		configuration.GovernedClients = map[string]config.GovernedClientConfig{
			"governed": {Authentication: config.ClientAuthenticationConfig{ClientID: "governed", Token: governedToken}},
		}
		configuration.ManagedClients = map[string]config.ManagedClientConfig{
			"managed": {
				Authentication: config.ClientAuthenticationConfig{ClientID: "managed", Token: managedToken},
				Configuration:  config.ManagedConfiguration{Revision: 1},
			},
		}
		return configuration
	}
	testCases := []struct {
		name     string
		change   func(*config.ServerConfig)
		wantMode authentication.Mode
		wantID   string
	}{
		{name: "Shared", wantMode: authentication.ModeShared, change: func(configuration *config.ServerConfig) {
			replacement := "replacement-shared-token-with-at-least-32-random-bytes"
			configuration.Authentication.SharedToken = &replacement
		}},
		{name: "Governed", wantMode: authentication.ModeGoverned, wantID: "governed", change: func(configuration *config.ServerConfig) {
			record := configuration.GovernedClients["governed"]
			record.Authentication.Token = "replacement-governed-token-with-at-least-32-random-bytes"
			configuration.GovernedClients["governed"] = record
		}},
		{name: "Managed", wantMode: authentication.ModeManaged, wantID: "managed", change: func(configuration *config.ServerConfig) {
			record := configuration.ManagedClients["managed"]
			record.Authentication.Token = "replacement-managed-token-with-at-least-32-random-bytes"
			configuration.ManagedClients["managed"] = record
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			current := base()
			candidate := base()
			testCase.change(&candidate)
			currentSnapshot, err := config.BuildAuthenticationSnapshot(current)
			if err != nil {
				t.Fatal(err)
			}
			candidateSnapshot, err := config.BuildAuthenticationSnapshot(candidate)
			if err != nil {
				t.Fatal(err)
			}
			store := authentication.NewStore(currentSnapshot)
			revoked := revokedAuthenticationContexts(store.Load(), candidateSnapshot, current, candidate)
			if len(revoked) != 1 || revoked[0].Mode != testCase.wantMode || revoked[0].ClientID != testCase.wantID {
				t.Fatalf("Token rotation revoked contexts %+v", revoked)
			}
		})
	}
}

func TestAuthenticationTokensChangedIncludesRecordOwnership(t *testing.T) {
	token := "client-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.GovernedClients = map[string]config.GovernedClientConfig{
		"client-one": {Authentication: config.ClientAuthenticationConfig{ClientID: "client-one", Token: token}},
	}

	unchanged := current
	unchanged.GovernedClients = map[string]config.GovernedClientConfig{
		"client-one": {Authentication: config.ClientAuthenticationConfig{ClientID: "client-one", Token: token}},
	}
	if authenticationTokensChanged(current, unchanged) {
		t.Fatal("equivalent authentication records were reported as changed")
	}

	migrated := config.DefaultServer()
	migrated.ManagedClients = map[string]config.ManagedClientConfig{
		"client-one": {Authentication: config.ClientAuthenticationConfig{ClientID: "client-one", Token: token}},
	}
	if !authenticationTokensChanged(current, migrated) {
		t.Fatal("authentication record mode migration was not reported as changed")
	}
}

func TestApplyConfigurationCandidateTokenChangeRevokesOnlyAffectedRecord(t *testing.T) {
	sharedToken := "shared-token-with-at-least-32-random-bytes"
	governedToken := "governed-token-with-at-least-32-random-bytes"
	replacementGovernedToken := "replacement-governed-token-with-at-least-32-random-bytes"
	managedToken := "managed-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.Authentication.SharedToken = &sharedToken
	current.GovernedClients = map[string]config.GovernedClientConfig{
		"governed-client": {
			Authentication: config.ClientAuthenticationConfig{ClientID: "governed-client", Token: governedToken},
		},
	}
	current.ManagedClients = map[string]config.ManagedClientConfig{
		"managed-client": {
			Authentication: config.ClientAuthenticationConfig{ClientID: "managed-client", Token: managedToken},
			Configuration: config.ManagedConfiguration{
				Revision: 1,
			},
		},
	}
	candidate := current
	candidate.GovernedClients = map[string]config.GovernedClientConfig{
		"governed-client": {
			Authentication: config.ClientAuthenticationConfig{ClientID: "governed-client", Token: replacementGovernedToken},
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
	if stats := registry.SnapshotStats(); stats != (session.Stats{Active: 1, Suspended: 1}) {
		t.Fatalf("unaffected sessions were not preserved after Token reload: %+v", stats)
	}
	for _, registered := range sessions {
		if registered.clientID == "governed-client" {
			if store.IsCurrent(registered.context) {
				t.Fatal("changed Governed authentication context remained current")
			}
			if accepted := serverTestHeartbeatAccepted(
				registry, registered.clientID, registered.sessionID, 1, time.Now(),
			); accepted {
				t.Fatal("changed Governed session remained registered")
			}
			if err := registered.client.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
				if _, err := registered.client.Read(make([]byte, 1)); err == nil {
					t.Fatal("changed Governed control connection remained open")
				}
			}
			continue
		}
		if !store.IsCurrent(registered.context) {
			t.Fatalf("unaffected authentication context for %s was rotated", registered.clientID)
		}
	}
	if !serverTestHeartbeatAccepted(registry, "shared-instance", "shared-session", 1, time.Now()) {
		t.Fatal("unaffected Shared session was revoked")
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
			Authentication: config.ClientAuthenticationConfig{ClientID: "governed-client", Token: governedToken},
			Permissions: config.GovernedPermissions{
				Proxies: config.GovernedProxyPermissions{
					TCP: &config.ProxyPermission{}, Limits: config.DefaultProxyPermissionLimits(),
				},
				Forwards: config.GovernedForwardPermissions{Limits: config.DefaultForwardPermissionLimits()},
			},
		},
	}
	current.ManagedClients = map[string]config.ManagedClientConfig{
		"managed-client": {
			Authentication: config.ClientAuthenticationConfig{ClientID: "managed-client", Token: managedToken},
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
	changedGoverned.Permissions.Proxies.Limits.MaxTotal = 1
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
		config.DefaultServer().Proxies.HTTP.HTTPConfig,
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
		proxyregistry.SyncRequest{
			Revision: 1,
			Proxies: []protocol.ProxyDeclaration{{
				Name:       "governed-proxy",
				Type:       protocol.ProxyTypeTCP,
				RemotePort: proxyPort,
			}},
		},
	)
	if result.Status != proxyregistry.SyncStatusApplied {
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

func TestApplyConfigurationCandidateHotReloadsForwardPolicy(t *testing.T) {
	token := "shared-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.Authentication.SharedToken = &token
	current.Generation = 3
	current.Forwards = config.ForwardServerConfig{
		Enabled: true,
		Rules: []config.ForwardIPRule{{
			IPRange: "10.0.0.0/8",
			TCP:     config.ForwardPortPermission{PortRanges: []config.PortRange{{Start: 5000, End: 5999}}},
		}},
	}
	snapshot, err := config.BuildAuthenticationSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		logger: logging.New("test"), configuration: newConfigurationManager(current),
		clientRegistry: session.NewRegistry(), authenticationStore: authentication.NewStore(snapshot),
		managed: newManagedCoordinator(),
	}
	candidate := current
	candidate.Forwards.Rules = []config.ForwardIPRule{{
		IPRange: "10.0.0.0/8",
		TCP:     config.ForwardPortPermission{PortRanges: []config.PortRange{{Start: 5000, End: 6999}}},
	}}
	if err := service.applyConfigurationCandidate(candidate); err != nil {
		t.Fatalf("hot reload Forward policy: %v", err)
	}
	updated := service.configuration.snapshot()
	if updated.Generation != 4 || !reflect.DeepEqual(updated.Forwards, candidate.Forwards) {
		t.Fatalf("Forward policy was not published: %+v", updated.Forwards)
	}
}

func TestApplyConfigurationCandidateRejectsInvalidForwardPolicyAtomically(t *testing.T) {
	token := "shared-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.Authentication.SharedToken = &token
	current.Generation = 8
	current.Forwards = config.ForwardServerConfig{
		Enabled: true,
		Rules: []config.ForwardIPRule{{
			IPRange: "10.0.0.0/8",
			UDP:     config.ForwardPortPermission{PortRanges: []config.PortRange{{Start: 53, End: 53}}},
		}},
	}
	snapshot, err := config.BuildAuthenticationSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		logger: logging.New("test"), configuration: newConfigurationManager(current),
		clientRegistry: session.NewRegistry(), authenticationStore: authentication.NewStore(snapshot),
		managed: newManagedCoordinator(),
	}
	candidate := current
	candidate.Forwards.Rules = nil
	if err := service.applyConfigurationCandidate(candidate); err == nil {
		t.Fatal("enabled Forward policy without rules was accepted")
	}
	updated := service.configuration.snapshot()
	if updated.Generation != 8 || !reflect.DeepEqual(updated.Forwards, current.Forwards) {
		t.Fatal("rejected Forward policy changed the active snapshot")
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
	current.Proxies.HTTPS = config.HTTPSConfig{
		ListenAddress: "127.0.0.1:8443",
		Certificates: []config.HTTPSCertificateConfig{{
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
		current.Proxies.HTTPS,
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
	candidate.Proxies.HTTPS = config.HTTPSConfig{
		ListenAddress: current.Proxies.HTTPS.ListenAddress,
		Certificates: []config.HTTPSCertificateConfig{{
			Domains:  []string{"localhost"},
			CertFile: replacementCertificateFile,
			KeyFile:  replacementKeyFile,
		}}}
	if err := service.applyConfigurationCandidate(candidate); err != nil {
		t.Fatalf("apply HTTPS certificate path update: %v", err)
	}
	if !reflect.DeepEqual(service.configuration.snapshot().Proxies.HTTPS, candidate.Proxies.HTTPS) {
		t.Fatal("HTTPS certificate paths were not published")
	}
	if certificateManager.snapshot.Load() == initialSnapshot {
		t.Fatal("HTTPS certificate path update did not replace the certificate")
	}
	activeSnapshot := certificateManager.snapshot.Load()
	invalidCandidate := candidate
	invalidCandidate.Proxies.HTTPS.Certificates = append(
		[]config.HTTPSCertificateConfig(nil),
		candidate.Proxies.HTTPS.Certificates...,
	)
	invalidCandidate.Proxies.HTTPS.Certificates[0].KeyFile = replacementCertificateFile
	if err := service.applyConfigurationCandidate(invalidCandidate); err == nil {
		t.Fatal("invalid HTTPS certificate path update was accepted")
	}
	if !reflect.DeepEqual(service.configuration.snapshot().Proxies.HTTPS, candidate.Proxies.HTTPS) {
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
