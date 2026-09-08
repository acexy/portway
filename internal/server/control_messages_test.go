package server

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
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

func TestServeControlMessagesRequiresInitialConfigurationSynchronization(t *testing.T) {
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
		!strings.Contains(err.Error(), "expected initial sync_configuration") {
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
		protocol.MessageSyncConfiguration,
		"request-one",
		protocol.SyncConfiguration{
			Revision: 1,
			Proxies: []protocol.ProxyDeclaration{
				{Name: "web", Type: protocol.ProxyTypeTCP, RemotePort: 8080},
			},
			Forwards: []protocol.ForwardDeclaration{},
		},
	); err != nil {
		t.Fatalf("write proxy synchronization: %v", err)
	}
	envelope, err := protocol.ReadControl(clientConnection)
	if err != nil {
		t.Fatal(err)
	}
	var rejection protocol.SyncConfigurationResult
	if err := protocol.DecodePayload(envelope, &rejection); err != nil {
		t.Fatal(err)
	}
	if rejection.Status != protocol.ConfigurationSyncStatusRejected || rejection.Error == nil ||
		rejection.Error.Code != protocol.ConfigurationErrorProxyTypeNotAllowed {
		t.Fatalf("unexpected capability rejection: %+v", rejection)
	}

	err = <-results
	if !errors.Is(err, errProxyRegistrationRejected) {
		t.Fatalf("unexpected capability validation error: %v", err)
	}
}
