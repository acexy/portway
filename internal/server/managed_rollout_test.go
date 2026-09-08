package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	forwardregistry "github.com/acexy/portway/internal/forward/registry"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	proxyregistry "github.com/acexy/portway/internal/proxy/registry"
	"github.com/acexy/portway/internal/session"
)

type failingManagedActivationExchange struct {
	writer     *control.Writer
	activation protocol.ManagedConfigActivate
}

func (exchange *failingManagedActivationExchange) prepare(
	context.Context,
	protocol.ManagedConfigPrepare,
	protocol.ManagedConfigStatus,
) error {
	return nil
}

func (exchange *failingManagedActivationExchange) activate(
	_ context.Context,
	activation protocol.ManagedConfigActivate,
) error {
	exchange.activation = activation
	return errors.New("activation failed")
}

func (exchange *failingManagedActivationExchange) controlWriter() *control.Writer {
	return exchange.writer
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
		config.DefaultServer().Proxies.HTTP.HTTPConfig,
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
			Authentication: config.ClientAuthenticationConfig{ClientID: "managed-client"},
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
		config.DefaultServer().Proxies.HTTP.HTTPConfig,
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
			Authentication: config.ClientAuthenticationConfig{ClientID: "managed-client"},
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

func TestManagedConfigurationActivationFailurePreservesForwardGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	broker := link.NewBroker(ctx)
	defer broker.Close()
	forwardRegistry := forwardregistry.New(
		broker,
		func(authentication.Context, protocol.ForwardDeclaration) (bool, bool) {
			return true, true
		},
		config.DefaultUDPConfig,
	)
	defer forwardRegistry.Close()
	proxyRegistry := proxyregistry.New(
		ctx,
		logging.New("test"),
		"127.0.0.1",
		broker,
		false,
		config.DefaultServer().Proxies.HTTP.HTTPConfig,
	)
	defer proxyRegistry.Close()
	var controlOutput bytes.Buffer
	writer := control.NewWriter(&controlOutput)
	authenticationContext := authentication.Context{
		Mode: authentication.ModeManaged, ClientID: "managed-client",
	}
	proxyRegistry.AttachAuthenticated(
		"managed-client", "session-one", writer, authenticationContext, 0,
	)
	oldDeclaration := protocol.ForwardDeclaration{
		Name: "database", Type: protocol.ForwardTypeTCP,
		TargetIP: "127.0.0.1", TargetPort: 5432,
	}
	oldResults, forwardError := forwardRegistry.Sync(
		"managed-client", "session-one", writer, authenticationContext, 10,
		[]protocol.ForwardDeclaration{oldDeclaration},
	)
	if forwardError != nil {
		t.Fatal(forwardError)
	}
	exchange := &failingManagedActivationExchange{writer: writer}
	service := &Service{proxyRegistry: proxyRegistry, forwardRegistry: forwardRegistry}
	err := service.applyManagedGeneration(
		ctx,
		"managed-client",
		"session-one",
		protocol.ManagedConfigPrepare{Revision: 2, Digest: "candidate"},
		protocol.SyncConfiguration{
			Revision: 2,
			Proxies:  []protocol.ProxyDeclaration{},
			Forwards: []protocol.ForwardDeclaration{{
				Name: "database", Type: protocol.ForwardTypeTCP,
				TargetIP: "127.0.0.1", TargetPort: 6432,
			}},
		},
		authenticationContext,
		exchange,
		true,
	)
	if err == nil || !strings.Contains(err.Error(), "activation failed") {
		t.Fatalf("activation failure = %v", err)
	}
	oldOffer := forwardRegistry.Offer(
		"managed-client",
		"session-one",
		protocol.RequestForwardLink{
			RequestID: "old", Name: oldDeclaration.Name, Type: oldDeclaration.Type,
			BindingID: oldResults[0].BindingID,
		},
	)
	if oldOffer.Error != nil {
		t.Fatalf("old Forward generation was not preserved: %+v", oldOffer.Error)
	}
	if len(exchange.activation.Forwards) != 1 {
		t.Fatalf("candidate Forward results = %+v", exchange.activation.Forwards)
	}
	candidateOffer := forwardRegistry.Offer(
		"managed-client",
		"session-one",
		protocol.RequestForwardLink{
			RequestID: "candidate", Name: oldDeclaration.Name, Type: oldDeclaration.Type,
			BindingID: exchange.activation.Forwards[0].BindingID,
		},
	)
	if candidateOffer.Error == nil {
		t.Fatal("failed candidate Forward generation was published")
	}
}

func TestManagedConfigurationRevisionMustIncrease(t *testing.T) {
	token := "managed-token-with-at-least-32-random-bytes"
	current := config.DefaultServer()
	current.ManagedClients = map[string]config.ManagedClientConfig{
		"managed-client": {
			Authentication: config.ClientAuthenticationConfig{ClientID: "managed-client", Token: token},
			Configuration: config.ManagedConfiguration{
				Revision: 2,
				Proxies:  []config.ProxyConfig{},
			},
		},
	}
	candidate := current
	candidate.ManagedClients = map[string]config.ManagedClientConfig{
		"managed-client": {
			Authentication: config.ClientAuthenticationConfig{ClientID: "managed-client", Token: token},
			Configuration: config.ManagedConfiguration{
				Revision: 2,
				Proxies: []config.ProxyConfig{{
					Name:   "ssh",
					Type:   "tcp",
					Local:  config.EndpointConfig{IP: "127.0.0.1", Port: 22},
					Public: config.ProxyPublicConfig{Port: 22022},
				}},
			},
		},
	}
	if err := validateManagedRevisionTransitions(current, candidate); err == nil {
		t.Fatal("managed configuration changed without increasing revision")
	}
}
