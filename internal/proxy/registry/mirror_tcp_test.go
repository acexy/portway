package registry

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
)

func TestMirrorTargetGuardRejectsStaleGenerations(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Registry, *mirrorGroup, *clientState, *tcpProxyBinding)
	}{
		{"closed registry", func(manager *Registry, _ *mirrorGroup, _ *clientState, _ *tcpProxyBinding) {
			manager.closed = true
		}},
		{"replaced group", func(manager *Registry, group *mirrorGroup, _ *clientState, _ *tcpProxyBinding) {
			manager.tcpMirrorGroups[group.port] = &mirrorGroup{}
		}},
		{"removed client", func(manager *Registry, _ *mirrorGroup, _ *clientState, _ *tcpProxyBinding) {
			delete(manager.clients, "client")
		}},
		{"inactive client", func(_ *Registry, _ *mirrorGroup, state *clientState, _ *tcpProxyBinding) {
			state.active = false
		}},
		{"replaced session", func(_ *Registry, _ *mirrorGroup, state *clientState, _ *tcpProxyBinding) {
			state.sessionID = "replacement"
		}},
		{"replaced writer", func(_ *Registry, _ *mirrorGroup, state *clientState, _ *tcpProxyBinding) {
			state.writer = control.NewWriter(io.Discard)
		}},
		{"replaced binding", func(_ *Registry, group *mirrorGroup, state *clientState, _ *tcpProxyBinding) {
			binding := &tcpProxyBinding{bindingID: "replacement"}
			group.tcpMembers["client"] = binding
			state.tcpProxies["proxy"] = binding
		}},
		{"removed proxy", func(_ *Registry, _ *mirrorGroup, state *clientState, _ *tcpProxyBinding) {
			delete(state.tcpProxies, "proxy")
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			binding := &tcpProxyBinding{
				bindingID: "binding", declaration: protocol.ProxyDeclaration{Name: "proxy"},
			}
			state := &clientState{
				active: true, sessionID: "session", writer: control.NewWriter(io.Discard),
				tcpProxies: map[string]*tcpProxyBinding{"proxy": binding},
			}
			group := &mirrorGroup{port: 1234, tcpMembers: map[string]*tcpProxyBinding{"client": binding}}
			manager := &Registry{
				clients:         map[string]*clientState{"client": state},
				tcpMirrorGroups: map[uint16]*mirrorGroup{group.port: group},
			}
			guard := mirrorTargetGuard{manager: manager, group: group}
			target := mirrorTCPLinkTarget("client", state, binding)
			guard.Lock()
			defer guard.Unlock()
			if !guard.IsCurrent(target) {
				t.Fatal("current target was rejected")
			}
			test.change(manager, group, state, binding)
			if guard.IsCurrent(target) {
				t.Fatalf("stale target was accepted: %s", test.name)
			}
			if guard.IsCurrent(link.Target{ClientID: "unknown"}) {
				t.Fatal("unknown client was accepted")
			}
		})
	}
}

func TestMirrorTCPAllLocalDialsFailThenRecover(t *testing.T) {
	manager := newTestTCPProxyManager(t)
	port := uint16(reserveTCPAddress(t).Port)
	if err := manager.ConfigureMirrorGroups(config.ProxyMirrorConfig{
		Governed: []config.ProxyMirrorGroupConfig{{
			Name: "recovery", Type: protocol.ProxyTypeTCP, Public: mirrorPublic(port),
			PrimaryClientID: "client-a", ClientIDs: []string{"client-a"},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	serverControl, clientControl := net.Pipe()
	defer serverControl.Close()
	defer clientControl.Close()
	manager.AttachAuthenticated("client-a", "session-a", control.NewWriter(serverControl),
		authentication.Context{Mode: authentication.ModeGoverned, ClientID: "client-a"}, 10)
	if result := manager.Sync("client-a", "session-a", "request-a", SyncRequest{
		Revision: 1, Proxies: []protocol.ProxyDeclaration{tcpProxyDeclaration("proxy-a", port)},
	}); result.Status != SyncStatusApplied {
		t.Fatalf("register mirror member: %+v", result)
	}
	manager.Activate("client-a", "session-a")
	attempts := make(chan struct{}, 10)
	var localReady atomic.Bool
	localConnections := make(chan net.Conn, 1)
	bindingDone := make(chan struct{}, 1)
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		for {
			envelope, err := protocol.ReadControl(clientControl)
			if err != nil {
				return
			}
			if envelope.Type != protocol.MessageOpenLink {
				continue
			}
			var request protocol.OpenLink
			if err := protocol.DecodePayload(envelope, &request); err != nil {
				return
			}
			if localReady.Load() {
				stream, local := net.Pipe()
				go func() {
					_ = manager.linkBroker.Bind(manager.context, stream, protocol.BindLink{
						ClientID: "client-a", SessionID: "session-a", LinkID: request.LinkID,
						ProxyType: protocol.ProxyTypeTCP, BindingID: request.BindingID, Ticket: request.Ticket,
					}, authentication.Context{Mode: authentication.ModeGoverned, ClientID: "client-a"})
					bindingDone <- struct{}{}
				}()
				if _, err := protocol.ReadControl(local); err != nil {
					_ = local.Close()
					return
				}
				localConnections <- local
				continue
			}
			manager.linkBroker.ReportFailure("client-a", "session-a", protocol.LinkFailed{
				LinkID: request.LinkID, Code: protocol.LinkErrorLocalDialFailed,
			})
			attempts <- struct{}{}
		}
	}()
	visitor, peer := net.Pipe()
	defer peer.Close()
	done := make(chan struct{})
	manager.mutex.Lock()
	group := manager.tcpMirrorGroups[port]
	manager.mutex.Unlock()
	go func() {
		manager.openMirrorVisitor(group, visitor)
		close(done)
	}()
	for attempt := 0; attempt < 2; attempt++ {
		select {
		case <-attempts:
		case <-time.After(3 * time.Second):
			t.Fatal("failed local dial was not retried")
		}
		if err := peer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := peer.Write([]byte("discard while unavailable")); err != nil {
			t.Fatalf("visitor stopped consuming input with all members unavailable: %v", err)
		}
	}
	localReady.Store(true)
	var local net.Conn
	select {
	case local = <-localConnections:
	case <-time.After(3 * time.Second):
		t.Fatal("all-unavailable session did not recover when its Primary became ready")
	}
	defer local.Close()
	_ = peer.SetDeadline(time.Now().Add(time.Second))
	_ = local.SetDeadline(time.Now().Add(time.Second))
	go func() { _, _ = local.Write([]byte("ready")) }()
	var ready [5]byte
	if _, err := io.ReadFull(peer, ready[:]); err != nil || string(ready[:]) != "ready" {
		t.Fatalf("recovered Primary did not retain response authority: %q, %v", ready, err)
	}
	if _, err := peer.Write([]byte("fresh")); err != nil {
		t.Fatal(err)
	}
	var received [5]byte
	if _, err := io.ReadFull(local, received[:]); err != nil || string(received[:]) != "fresh" {
		t.Fatalf("recovery replayed old data or lost fresh input: %q, %v", received, err)
	}
	_ = local.Close()
	_ = peer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("visitor closure left a retry task running")
	}
	manager.mutex.Lock()
	remaining := len(group.tcpSessions)
	manager.mutex.Unlock()
	if remaining != 0 {
		t.Fatalf("closed visitor retained %d mirror sessions", remaining)
	}
	select {
	case <-bindingDone:
	case <-time.After(time.Second):
		t.Fatal("closed visitor retained the broker binding task")
	}
	stats := manager.linkBroker.SnapshotStats()
	if stats.Pending != 0 || stats.Active != 0 {
		t.Fatalf("closed visitor retained links: %+v", stats)
	}
	_ = clientControl.Close()
	<-controlDone
}
