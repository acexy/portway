package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/logging"
	proxyregistry "github.com/acexy/portway/internal/proxy/registry"
	"github.com/acexy/portway/internal/session"
)

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
		config.DefaultServer().Proxies.HTTP.HTTPConfig,
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
