package server

import (
	"net"
	"testing"

	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
)

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
			[]string{"tcp", "json-control"},
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
			[]string{"json-control"},
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
