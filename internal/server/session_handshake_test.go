package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	proxyregistry "github.com/acexy/portway/internal/proxy/registry"
	"github.com/acexy/portway/internal/session"
	"github.com/acexy/portway/internal/transport"
)

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
			Authentication: config.ClientAuthenticationConfig{ClientID: "managed-client", Token: token},
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
		configuration.Proxies.HTTP.HTTPConfig,
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
