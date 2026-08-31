package registry

import (
	"bytes"
	"context"
	"testing"

	"github.com/acexy/portway/internal/authentication"
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
	})
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
