package registry

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
)

func TestPolicyDisablesAndReactivatesDormantBinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	broker := link.NewBroker(ctx)
	defer broker.Close()

	enabled := false
	registry := New(broker, func(authentication.Context, protocol.ForwardDeclaration) (bool, bool) {
		return true, enabled
	}, config.DefaultUDPConfig)
	declaration := protocol.ForwardDeclaration{
		Name: "database", Type: protocol.ForwardTypeTCP, TargetIP: "127.0.0.1", TargetPort: 5432,
	}
	var messages bytes.Buffer
	results, forwardError := registry.Sync(
		"client", "session", control.NewWriter(&messages), authentication.Context{Mode: authentication.ModeShared},
		10, []protocol.ForwardDeclaration{declaration},
	)
	if forwardError != nil || len(results) != 1 || results[0].Active {
		t.Fatalf("dormant synchronization result = %+v, error = %v", results, forwardError)
	}

	enabled = true
	registry.ApplyPolicy(2, func(authentication.Context, protocol.ForwardDeclaration) bool { return true })
	offer := registry.Offer("client", "session", protocol.RequestForwardLink{
		RequestID: "request", Name: declaration.Name, Type: declaration.Type, BindingID: results[0].BindingID,
	})
	if offer.Error != nil {
		t.Fatalf("reactivated Binding rejected Forward Link: %+v", offer.Error)
	}

	enabled = false
	registry.ApplyPolicy(3, func(authentication.Context, protocol.ForwardDeclaration) bool { return true })
	offer = registry.Offer("client", "session", protocol.RequestForwardLink{
		RequestID: "disabled", Name: declaration.Name, Type: declaration.Type, BindingID: results[0].BindingID,
	})
	if offer.Error == nil {
		t.Fatal("disabled Binding accepted Forward Link")
	}
	if !bytes.Contains(messages.Bytes(), []byte(protocol.MessageForwardBindingActivated)) ||
		!bytes.Contains(messages.Bytes(), []byte(protocol.MessageForwardBindingRevoked)) {
		t.Fatalf("policy transition messages = %q", messages.String())
	}
}

func TestUDPBindingCarriesServerRuntimeLimits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	broker := link.NewBroker(ctx)
	defer broker.Close()
	configuration := config.DefaultUDPConfig()
	configuration.MaxDatagramSize = 1234
	registry := New(
		broker,
		func(authentication.Context, protocol.ForwardDeclaration) (bool, bool) { return true, true },
		func() config.UDPConfig { return configuration },
	)
	results, forwardError := registry.Sync(
		"client", "session", control.NewWriter(&bytes.Buffer{}), authentication.Context{}, 10,
		[]protocol.ForwardDeclaration{{
			Name: "dns", Type: protocol.ForwardTypeUDP, TargetIP: "127.0.0.1", TargetPort: 53,
		}},
	)
	if forwardError != nil || len(results) != 1 || results[0].UDP == nil ||
		results[0].UDP.MaxDatagramSize != configuration.MaxDatagramSize {
		t.Fatalf("UDP Forward limits = %+v, error = %v", results, forwardError)
	}
}

func TestSyncTransactionRollbackPreservesPublishedBinding(t *testing.T) {
	broker := link.NewBroker(context.Background())
	defer broker.Close()
	registry := New(
		broker,
		func(authentication.Context, protocol.ForwardDeclaration) (bool, bool) { return true, true },
		config.DefaultUDPConfig,
	)
	declaration := protocol.ForwardDeclaration{
		Name: "database", Type: protocol.ForwardTypeTCP,
		TargetIP: "127.0.0.1", TargetPort: 5432,
	}
	results, forwardError := registry.Sync(
		"client", "session", nil, authentication.Context{}, 10,
		[]protocol.ForwardDeclaration{declaration},
	)
	if forwardError != nil {
		t.Fatal(forwardError)
	}
	transaction, forwardError := registry.BeginSync(
		"client", "session", nil, authentication.Context{}, 10,
		[]protocol.ForwardDeclaration{{
			Name: "database", Type: protocol.ForwardTypeTCP,
			TargetIP: "127.0.0.1", TargetPort: 5433,
		}},
	)
	if forwardError != nil {
		t.Fatal(forwardError)
	}
	transaction.Rollback()
	offer := registry.Offer("client", "session", protocol.RequestForwardLink{
		RequestID: "request", Name: declaration.Name, Type: declaration.Type,
		BindingID: results[0].BindingID,
	})
	if offer.Error != nil {
		t.Fatalf("rollback replaced the published Binding: %+v", offer.Error)
	}
}

func TestSyncTransactionDoesNotBlockAndRejectsStaleCommit(t *testing.T) {
	broker := link.NewBroker(context.Background())
	defer broker.Close()
	registry := New(
		broker,
		func(authentication.Context, protocol.ForwardDeclaration) (bool, bool) { return true, true },
		config.DefaultUDPConfig,
	)
	declaration := protocol.ForwardDeclaration{
		Name: "database", Type: protocol.ForwardTypeTCP,
		TargetIP: "127.0.0.1", TargetPort: 5432,
	}
	if _, forwardError := registry.Sync(
		"client", "session", nil, authentication.Context{}, 10,
		[]protocol.ForwardDeclaration{declaration},
	); forwardError != nil {
		t.Fatal(forwardError)
	}
	candidate, forwardError := registry.BeginSync(
		"client", "session", nil, authentication.Context{}, 10,
		[]protocol.ForwardDeclaration{{
			Name: "database", Type: protocol.ForwardTypeTCP,
			TargetIP: "127.0.0.1", TargetPort: 6432,
		}},
	)
	if forwardError != nil {
		t.Fatal(forwardError)
	}
	synchronized := make(chan *protocol.ForwardError, 1)
	go func() {
		_, syncError := registry.Sync(
			"client", "session", nil, authentication.Context{}, 10,
			[]protocol.ForwardDeclaration{declaration},
		)
		synchronized <- syncError
	}()
	select {
	case syncError := <-synchronized:
		if syncError != nil {
			t.Fatal(syncError)
		}
	case <-time.After(time.Second):
		t.Fatal("prepared Forward transaction blocked another synchronization")
	}
	if candidate.Commit() {
		t.Fatal("stale Forward candidate replaced a newer generation")
	}
}
