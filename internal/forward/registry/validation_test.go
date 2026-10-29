package registry

import (
	"fmt"
	"testing"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/limits"
	"github.com/acexy/portway/internal/protocol"
)

func TestForwardValidationEnforcesWireBoundary(t *testing.T) {
	valid := protocol.ForwardDeclaration{Name: "target", Type: protocol.ForwardTypeTCP, TargetIP: "127.0.0.1", TargetPort: 80}
	for _, test := range []struct {
		name   string
		mutate func(*protocol.ForwardDeclaration)
	}{
		{"invalid_name", func(d *protocol.ForwardDeclaration) { d.Name = "bad\x00name" }},
		{"hostname", func(d *protocol.ForwardDeclaration) { d.TargetIP = "localhost" }},
		{"noncanonical_ip", func(d *protocol.ForwardDeclaration) { d.TargetIP = "0:0:0:0:0:0:0:1" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry := newSessionRegistry(t)
			declaration := valid
			test.mutate(&declaration)
			transaction, failure := registry.BeginSync("client", "session", nil, authentication.Context{}, 0, []protocol.ForwardDeclaration{declaration})
			if transaction != nil || failure == nil || failure.Code != protocol.ForwardErrorInvalidForward {
				t.Fatalf("invalid wire declaration accepted: transaction=%v failure=%v", transaction != nil, failure)
			}
			if len(registry.sessions) != 0 {
				t.Fatal("invalid declaration reserved session ownership")
			}
		})
	}
	registry := newSessionRegistry(t)
	declarations := make([]protocol.ForwardDeclaration, limits.HardMaxBindingsPerClient+1)
	for index := range declarations {
		declarations[index] = valid
		declarations[index].Name = fmt.Sprintf("target-%d", index)
	}
	if failure := registry.Validate(authentication.Context{}, declarations[:limits.HardMaxBindingsPerClient]); failure != nil {
		t.Fatal(failure)
	}
	if failure := registry.Validate(authentication.Context{}, declarations); failure == nil || failure.Code != protocol.ForwardErrorLimitExceeded {
		t.Fatalf("hard limit not enforced: %v", failure)
	}
}
