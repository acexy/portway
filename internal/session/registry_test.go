package session

import (
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
)

func TestClientRegistryRejectsDuplicateActiveClient(t *testing.T) {
	registry := NewRegistry()
	now := time.Now()
	serverConnection, peerConnection := net.Pipe()
	defer serverConnection.Close()
	defer peerConnection.Close()

	_, created, _, sessionError := registry.Register(
		"client-one",
		"",
		"session-one",
		serverConnection,
		now,
	)
	if !created || sessionError != nil {
		t.Fatalf("initial registration failed: created=%t error=%v", created, sessionError)
	}
	if !registry.Activate("client-one", "session-one", now) {
		t.Fatal("initial session was not activated")
	}

	_, _, _, sessionError = registry.Register(
		"client-one",
		"",
		"session-two",
		serverConnection,
		now,
	)
	if sessionError == nil || sessionError.Code != protocol.SessionErrorClientIDAlreadyOnline {
		t.Fatalf("expected duplicate client error, got %#v", sessionError)
	}
	if sessionError.Retryable {
		t.Fatal("duplicate active client error must be permanent")
	}
}

func TestClientRegistryReportsRecoveryPendingForMatchingActiveSession(t *testing.T) {
	registry := NewRegistry()
	now := time.Now()
	serverConnection, peerConnection := net.Pipe()
	defer serverConnection.Close()
	defer peerConnection.Close()

	registry.Register("client-one", "", "session-one", serverConnection, now)
	registry.Activate("client-one", "session-one", now)

	_, _, _, sessionError := registry.Register(
		"client-one",
		"session-one",
		"session-two",
		serverConnection,
		now.Add(time.Second),
	)
	if sessionError == nil ||
		sessionError.Code != protocol.SessionErrorClientIDRecoveryPending ||
		!sessionError.Retryable {
		t.Fatalf("expected retryable recovery pending error, got %#v", sessionError)
	}
}

func TestClientRegistryRejectsMismatchedActiveSession(t *testing.T) {
	registry := NewRegistry()
	now := time.Now()
	serverConnection, peerConnection := net.Pipe()
	defer serverConnection.Close()
	defer peerConnection.Close()

	registry.Register("client-one", "", "session-one", serverConnection, now)
	registry.Activate("client-one", "session-one", now)

	_, _, _, sessionError := registry.Register(
		"client-one",
		"different-session",
		"session-two",
		serverConnection,
		now.Add(time.Second),
	)
	if sessionError == nil ||
		sessionError.Code != protocol.SessionErrorClientIDAlreadyOnline ||
		sessionError.Retryable {
		t.Fatalf("expected permanent duplicate client error, got %#v", sessionError)
	}
}

func TestClientRegistryKeepsInitializingSessionOutOfHeartbeatLifecycle(t *testing.T) {
	registry := NewRegistry()
	now := time.Now()
	serverConnection, peerConnection := net.Pipe()
	defer serverConnection.Close()
	defer peerConnection.Close()

	registry.Register("client-one", "", "session-one", serverConnection, now)

	_, _, _, sessionError := registry.Register(
		"client-one",
		"",
		"session-two",
		serverConnection,
		now.Add(time.Second),
	)
	if sessionError == nil ||
		sessionError.Code != protocol.SessionErrorClientIDRecoveryPending ||
		!sessionError.Retryable {
		t.Fatalf("expected initializing recovery pending error, got %#v", sessionError)
	}
	_, _, _, sessionError = registry.Register(
		"client-one",
		"different-session",
		"session-three",
		serverConnection,
		now.Add(time.Second),
	)
	if sessionError == nil ||
		sessionError.Code != protocol.SessionErrorClientIDAlreadyOnline ||
		sessionError.Retryable {
		t.Fatalf("expected initializing duplicate client error, got %#v", sessionError)
	}
	if heartbeatAccepted(registry, "client-one", "session-one", 1, now.Add(time.Second)) {
		t.Fatal("initializing session accepted a heartbeat")
	}
	suspended, expired := registry.Sweep(
		now.Add(time.Hour),
		10*time.Second,
		60*time.Second,
	)
	if len(suspended) != 0 || len(expired) != 0 {
		t.Fatalf("initializing session entered heartbeat lifecycle: %v %v", suspended, expired)
	}
}

func TestClientRegistryRejectsNonIncreasingHeartbeatSequence(t *testing.T) {
	registry := NewRegistry()
	now := time.Now()
	serverConnection, peerConnection := net.Pipe()
	defer serverConnection.Close()
	defer peerConnection.Close()

	registry.Register("client-one", "", "session-one", serverConnection, now)
	registry.Activate("client-one", "session-one", now)
	if heartbeatAccepted(registry, "client-one", "session-one", 0, now.Add(time.Second)) {
		t.Fatal("zero heartbeat sequence was accepted")
	}
	accepted, reactivated := registry.Heartbeat(
		"client-one",
		"session-one",
		1,
		now.Add(time.Second),
	)
	if !accepted || reactivated {
		t.Fatal("first heartbeat sequence was rejected")
	}
	if heartbeatAccepted(registry, "client-one", "session-one", 1, now.Add(2*time.Second)) {
		t.Fatal("duplicate heartbeat sequence was accepted")
	}
	if heartbeatAccepted(registry, "client-one", "session-one", 0, now.Add(2*time.Second)) {
		t.Fatal("regressed heartbeat sequence was accepted")
	}
	if !heartbeatAccepted(registry, "client-one", "session-one", 2, now.Add(3*time.Second)) {
		t.Fatal("increasing heartbeat sequence was rejected")
	}
	registry.Disconnect("client-one", "session-one", now.Add(4*time.Second))
	accepted, reactivated = registry.Heartbeat(
		"client-one",
		"session-one",
		3,
		now.Add(5*time.Second),
	)
	if !accepted || !reactivated {
		t.Fatal("suspended session heartbeat did not report reactivation")
	}
}

func TestClientRegistryRevokesOnlyMatchingAuthenticationGeneration(t *testing.T) {
	registry := NewRegistry()
	now := time.Now()
	firstServer, firstPeer := net.Pipe()
	defer firstServer.Close()
	defer firstPeer.Close()
	secondServer, secondPeer := net.Pipe()
	defer secondServer.Close()
	defer secondPeer.Close()
	first := authentication.Context{
		Mode:         authentication.ModeGoverned,
		ClientID:     "client-one",
		CredentialID: authentication.Selector("first-token-with-at-least-32-random-bytes"),
		Generation:   1,
	}
	second := authentication.Context{
		Mode:         authentication.ModeGoverned,
		ClientID:     "client-two",
		CredentialID: authentication.Selector("second-token-with-at-least-32-random-bytes"),
		Generation:   1,
	}
	registry.RegisterAuthenticated(
		"client-one", "", "session-one", firstServer, now, first,
	)
	registry.Activate("client-one", "session-one", now)
	registry.RegisterAuthenticated(
		"client-two", "", "session-two", secondServer, now, second,
	)
	registry.Activate("client-two", "session-two", now)

	revoked := registry.RevokeAuthentication([]authentication.Context{first})
	if len(revoked) != 1 || revoked[0].ClientID != "client-one" {
		t.Fatalf("unexpected revoked sessions: %#v", revoked)
	}
	if !heartbeatAccepted(registry, "client-two", "session-two", 1, now.Add(time.Second)) {
		t.Fatal("unrelated session was revoked")
	}
}

func TestClientRegistryResumesSuspendedClient(t *testing.T) {
	registry := NewRegistry()
	now := time.Now()
	oldConnection, oldPeer := net.Pipe()
	defer oldConnection.Close()
	defer oldPeer.Close()
	newConnection, newPeer := net.Pipe()
	defer newConnection.Close()
	defer newPeer.Close()

	registry.Register("client-one", "", "session-one", oldConnection, now)
	registry.Activate("client-one", "session-one", now)
	registry.Disconnect("client-one", "session-one", now.Add(time.Second))

	resumed, created, previousConnection, sessionError := registry.Register(
		"client-one",
		"session-one",
		"session-two",
		newConnection,
		now.Add(2*time.Second),
	)
	if sessionError != nil || !resumed || created {
		t.Fatalf(
			"resume failed: resumed=%t created=%t error=%v",
			resumed,
			created,
			sessionError,
		)
	}
	if previousConnection != oldConnection {
		t.Fatal("resume did not return the previous connection")
	}
	if !registry.Activate("client-one", "session-two", now.Add(2*time.Second)) {
		t.Fatal("resumed session was not activated")
	}

	// A delayed cleanup from the old handler must not suspend the new session.
	registry.Disconnect("client-one", "session-one", now.Add(3*time.Second))
	if !heartbeatAccepted(registry, "client-one", "session-two", 1, now.Add(4*time.Second)) {
		t.Fatal("new session was changed by stale cleanup")
	}
}

func TestClientRegistryRejectsPreviousSessionIDAfterSuccessfulResume(t *testing.T) {
	registry := NewRegistry()
	now := time.Now()
	oldConnection, oldPeer := net.Pipe()
	defer oldConnection.Close()
	defer oldPeer.Close()
	newConnection, newPeer := net.Pipe()
	defer newConnection.Close()
	defer newPeer.Close()

	registry.Register("client-one", "", "session-one", oldConnection, now)
	registry.Activate("client-one", "session-one", now)
	registry.Disconnect("client-one", "session-one", now.Add(time.Second))
	resumed, _, _, sessionError := registry.Register(
		"client-one", "session-one", "session-two", newConnection, now.Add(2*time.Second),
	)
	if !resumed || sessionError != nil ||
		!registry.Activate("client-one", "session-two", now.Add(2*time.Second)) {
		t.Fatal("failed to establish the resumed session")
	}
	registry.Disconnect("client-one", "session-two", now.Add(3*time.Second))

	_, _, _, sessionError = registry.Register(
		"client-one", "session-one", "session-three", oldConnection, now.Add(4*time.Second),
	)
	if sessionError == nil ||
		sessionError.Code != protocol.SessionErrorResumeSessionMismatch ||
		sessionError.Retryable {
		t.Fatalf("previous session ID remained recoverable: %#v", sessionError)
	}
}

func TestClientRegistryEnforcesClientCapacity(t *testing.T) {
	registry := NewRegistryWithLimit(1)
	now := time.Now()
	firstConnection, firstPeer := net.Pipe()
	defer firstConnection.Close()
	defer firstPeer.Close()
	secondConnection, secondPeer := net.Pipe()
	defer secondConnection.Close()
	defer secondPeer.Close()

	_, created, _, sessionError := registry.Register(
		"client-one", "", "session-one", firstConnection, now,
	)
	if !created || sessionError != nil {
		t.Fatal("first client was not admitted")
	}
	_, _, _, sessionError = registry.Register(
		"client-two", "", "session-two", secondConnection, now,
	)
	if sessionError == nil ||
		sessionError.Code != protocol.SessionErrorServerCapacityReached ||
		!sessionError.Retryable {
		t.Fatalf("expected retryable server capacity error, got %#v", sessionError)
	}
}

func TestClientRegistryReportsRecoveryPendingWithoutSessionID(t *testing.T) {
	registry := NewRegistry()
	now := time.Now()
	serverConnection, peerConnection := net.Pipe()
	defer serverConnection.Close()
	defer peerConnection.Close()

	registry.Register("client-one", "", "session-one", serverConnection, now)
	registry.Activate("client-one", "session-one", now)
	registry.Disconnect("client-one", "session-one", now.Add(time.Second))

	_, _, _, sessionError := registry.Register(
		"client-one",
		"",
		"session-two",
		serverConnection,
		now.Add(2*time.Second),
	)
	if sessionError == nil ||
		sessionError.Code != protocol.SessionErrorClientIDRecoveryPending ||
		!sessionError.Retryable {
		t.Fatalf("expected retryable recovery pending error, got %#v", sessionError)
	}
}

func TestClientRegistryExpiresAfterRecoveryWindow(t *testing.T) {
	registry := NewRegistry()
	now := time.Now()
	serverConnection, peerConnection := net.Pipe()
	defer serverConnection.Close()
	defer peerConnection.Close()

	registry.Register("client-one", "", "session-one", serverConnection, now)
	registry.Activate("client-one", "session-one", now)
	suspendedClientIDs, expiredClients := registry.Sweep(
		now.Add(10*time.Second),
		10*time.Second,
		60*time.Second,
	)
	if len(suspendedClientIDs) != 1 || len(expiredClients) != 0 {
		t.Fatalf(
			"unexpected suspension result: suspended=%v expired=%v",
			suspendedClientIDs,
			expiredClients,
		)
	}

	_, expiredClients = registry.Sweep(
		now.Add(70*time.Second),
		10*time.Second,
		60*time.Second,
	)
	if len(expiredClients) != 1 || expiredClients[0].ClientID != "client-one" {
		t.Fatalf("unexpected expiration result: %#v", expiredClients)
	}
	if heartbeatAccepted(registry, "client-one", "session-one", 1, now.Add(71*time.Second)) {
		t.Fatal("expired client remained registered")
	}
}

func heartbeatAccepted(
	registry *Registry,
	clientID string,
	sessionID string,
	sequence uint64,
	now time.Time,
) bool {
	accepted, _ := registry.Heartbeat(clientID, sessionID, sequence, now)
	return accepted
}
