package registry

import (
	"context"
	"testing"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
)

func newSessionRegistry(t testing.TB) *Registry {
	t.Helper()
	broker := link.NewBroker(context.Background())
	t.Cleanup(broker.Close)
	registry := New(broker,
		func(authentication.Context, protocol.ForwardDeclaration) (bool, bool) { return true, true },
		config.DefaultUDPConfig, func(string, string) bool { return true },
	)
	t.Cleanup(registry.Close)
	return registry
}

func TestEmptySessionGenerationRejectsStaleTransaction(t *testing.T) {
	for _, transition := range []string{"publish_empty", "remove", "remove_and_prepare"} {
		t.Run(transition, func(t *testing.T) {
			registry := newSessionRegistry(t)
			stale, failure := registry.BeginSync("client", "session", nil, authentication.Context{}, 0,
				[]protocol.ForwardDeclaration{{Name: "target", Type: protocol.ForwardTypeTCP, TargetIP: "127.0.0.1", TargetPort: 80}},
			)
			if failure != nil {
				t.Fatal(failure)
			}
			defer stale.Retire()
			if transition == "publish_empty" {
				if _, failure := registry.Sync("client", "session", nil, authentication.Context{}, 0, nil); failure != nil {
					t.Fatal(failure)
				}
			} else {
				registry.Remove("client", "session")
				if transition == "remove_and_prepare" {
					replacement, failure := registry.BeginSync("client", "session", nil, authentication.Context{}, 0, nil)
					if failure != nil {
						t.Fatal(failure)
					}
					defer replacement.Rollback()
				}
			}
			companionCalled := false
			if stale.CommitWith(func() bool { companionCalled = true; return true }) {
				t.Error("stale transaction published after session generation changed")
			}
			if companionCalled || registry.SnapshotStats().Bindings != 0 {
				t.Error("stale transaction affected the companion or published bindings")
			}
		})
	}
}

func TestSessionPublicationAndRemovalAreIsolated(t *testing.T) {
	registry := newSessionRegistry(t)
	declaration := []protocol.ForwardDeclaration{{Name: "target", Type: protocol.ForwardTypeTCP, TargetIP: "127.0.0.1", TargetPort: 80}}
	pending, failure := registry.BeginSync("client", "new", nil, authentication.Context{}, 0, declaration)
	if failure != nil {
		t.Fatal(failure)
	}
	for _, sessionID := range []string{"old", "other"} {
		if _, failure := registry.Sync("client", sessionID, nil, authentication.Context{}, 0, declaration); failure != nil {
			t.Fatal(failure)
		}
	}
	registry.Remove("client", "old")
	if !pending.Commit() {
		t.Fatal("unrelated session changes invalidated the pending generation")
	}
	if stats := registry.SnapshotStats(); stats.Bindings != 2 || stats.ActiveBindings != 2 {
		t.Fatalf("unexpected surviving bindings: %+v", stats)
	}
	registry.Remove("client", "old")
	if stats := registry.SnapshotStats(); stats.Bindings != 2 {
		t.Fatalf("late removal affected a different session: %+v", stats)
	}
}
