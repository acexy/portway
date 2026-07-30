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
	registry.RegisterAuthenticated(
		"client-two", "", "session-two", secondServer, now, second,
	)

	revoked := registry.RevokeAuthentication([]authentication.Context{first})
	if len(revoked) != 1 || revoked[0].ClientID != "client-one" {
		t.Fatalf("unexpected revoked sessions: %#v", revoked)
	}
	if !registry.Heartbeat("client-two", "session-two", now.Add(time.Second)) {
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

	// A delayed cleanup from the old handler must not suspend the new session.
	registry.Disconnect("client-one", "session-one", now.Add(3*time.Second))
	if !registry.Heartbeat("client-one", "session-two", now.Add(4*time.Second)) {
		t.Fatal("new session was changed by stale cleanup")
	}
}

func TestClientRegistryExpiresAfterRecoveryWindow(t *testing.T) {
	registry := NewRegistry()
	now := time.Now()
	serverConnection, peerConnection := net.Pipe()
	defer serverConnection.Close()
	defer peerConnection.Close()

	registry.Register("client-one", "", "session-one", serverConnection, now)
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
	if registry.Heartbeat("client-one", "session-one", now.Add(71*time.Second)) {
		t.Fatal("expired client remained registered")
	}
}
