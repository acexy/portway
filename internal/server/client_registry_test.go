package server

import (
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/protocol"
)

func TestClientRegistryRejectsDuplicateActiveClient(t *testing.T) {
	registry := newClientRegistry()
	now := time.Now()
	serverConnection, peerConnection := net.Pipe()
	defer serverConnection.Close()
	defer peerConnection.Close()

	_, created, _, sessionError := registry.register(
		"client-one",
		"",
		"session-one",
		serverConnection,
		now,
	)
	if !created || sessionError != nil {
		t.Fatalf("initial registration failed: created=%t error=%v", created, sessionError)
	}

	_, _, _, sessionError = registry.register(
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

func TestClientRegistryResumesSuspendedClient(t *testing.T) {
	registry := newClientRegistry()
	now := time.Now()
	oldConnection, oldPeer := net.Pipe()
	defer oldConnection.Close()
	defer oldPeer.Close()
	newConnection, newPeer := net.Pipe()
	defer newConnection.Close()
	defer newPeer.Close()

	registry.register("client-one", "", "session-one", oldConnection, now)
	registry.disconnect("client-one", "session-one", now.Add(time.Second))

	resumed, created, previousConnection, sessionError := registry.register(
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
	registry.disconnect("client-one", "session-one", now.Add(3*time.Second))
	if !registry.heartbeat("client-one", "session-two", now.Add(4*time.Second)) {
		t.Fatal("new session was changed by stale cleanup")
	}
}

func TestClientRegistryExpiresAfterRecoveryWindow(t *testing.T) {
	registry := newClientRegistry()
	now := time.Now()
	serverConnection, peerConnection := net.Pipe()
	defer serverConnection.Close()
	defer peerConnection.Close()

	registry.register("client-one", "", "session-one", serverConnection, now)
	suspendedClientIDs, expiredClients := registry.sweep(
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

	_, expiredClients = registry.sweep(
		now.Add(70*time.Second),
		10*time.Second,
		60*time.Second,
	)
	if len(expiredClients) != 1 || expiredClients[0].clientID != "client-one" {
		t.Fatalf("unexpected expiration result: %#v", expiredClients)
	}
	if registry.heartbeat("client-one", "session-one", now.Add(71*time.Second)) {
		t.Fatal("expired client remained registered")
	}
}
