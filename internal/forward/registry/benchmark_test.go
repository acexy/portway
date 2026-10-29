package registry

import (
	"fmt"
	"testing"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
)

func BenchmarkForwardSessionSync(b *testing.B) {
	for _, otherSessions := range []int{0, 255} {
		b.Run(fmt.Sprintf("OtherSessions%d", otherSessions), func(b *testing.B) {
			registry := newSessionRegistry(b)
			declarations := make([]protocol.ForwardDeclaration, 64)
			for index := range declarations {
				declarations[index] = protocol.ForwardDeclaration{
					Name: fmt.Sprintf("target-%d", index), Type: protocol.ForwardTypeTCP,
					TargetIP: "127.0.0.1", TargetPort: 80,
				}
			}
			for index := range otherSessions {
				if _, failure := registry.Sync(fmt.Sprintf("client-%d", index), "session", nil,
					authentication.Context{}, 0, declarations); failure != nil {
					b.Fatal(failure)
				}
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, failure := registry.Sync("target-client", "session", nil,
					authentication.Context{}, 0, declarations[:1]); failure != nil {
					b.Fatal(failure)
				}
			}
		})
	}
}
