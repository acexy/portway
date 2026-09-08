package registry

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/proxy/mirror"
)

func TestMirrorReloadPreservesLiveSessionsAndSwitchesResponder(t *testing.T) {
	manager := newTestTCPProxyManager(t)
	port := uint16(reserveTCPAddress(t).Port)
	otherPort := uint16(reserveTCPAddress(t).Port)
	configuration := config.ProxyMirrorConfig{Governed: []config.ProxyMirrorGroupConfig{
		{Name: "changed", Type: protocol.ProxyTypeTCP, Public: mirrorPublic(port), PrimaryClientID: "a", ClientIDs: []string{"a", "b"}},
		{Name: "unchanged", Type: protocol.ProxyTypeTCP, Public: mirrorPublic(otherPort), PrimaryClientID: "a", ClientIDs: []string{"a", "b"}},
	}}
	if err := manager.ConfigureMirrorGroups(configuration); err != nil {
		t.Fatal(err)
	}
	for _, client := range []string{"a", "b"} {
		manager.AttachAuthenticated(client, client, control.NewWriter(io.Discard), authentication.Context{Mode: authentication.ModeGoverned, ClientID: client}, 10)
		result := manager.Sync(client, client, "request-"+client, SyncRequest{Revision: 1, Proxies: []protocol.ProxyDeclaration{tcpProxyDeclaration("first", port), tcpProxyDeclaration("second", otherPort)}})
		if result.Status != SyncStatusApplied {
			t.Fatalf("sync: %+v", result)
		}
		manager.Activate(client, client)
	}
	type running struct {
		session  *mirror.TCPSession
		peer     net.Conn
		backends map[string]net.Conn
		done     chan struct{}
	}
	sessions := make([]running, 0, 2)
	for _, p := range []uint16{port, otherPort} {
		visitor, peer := net.Pipe()
		ctx, cancel := context.WithCancel(manager.context)
		manager.mutex.Lock()
		group := manager.tcpMirrorGroups[p]
		manager.mutex.Unlock()
		streams := make(map[string]net.Conn)
		run := running{peer: peer, backends: make(map[string]net.Conn), done: make(chan struct{})}
		for _, client := range []string{"a", "b"} {
			stream, backend := net.Pipe()
			streams[client] = stream
			run.backends[client] = backend
			t.Cleanup(func() { stream.Close(); backend.Close() })
		}
		session := mirror.NewTCPSession(ctx, visitor, mirrorTargetGuard{manager: manager, group: group},
			func(_ context.Context, target link.Target) (net.Conn, error) { return streams[target.ClientID], nil })
		run.session = session
		if !manager.addMirrorTCPSession(group, session) {
			t.Fatal("session rejected")
		}
		targets := manager.snapshotMirrorTCPTargets(group)
		go func() { defer close(run.done); session.Serve(targets) }()
		t.Cleanup(func() {
			cancel()
			peer.Close()
			select {
			case <-run.done:
			case <-time.After(time.Second):
				t.Error("mirror session did not stop")
			}
			manager.removeMirrorTCPSession(group, session)
		})
		for _, target := range targets {
			select {
			case <-session.AddTarget(target):
			case <-time.After(time.Second):
				t.Fatal("mirror member did not start")
			}
		}
		sessions = append(sessions, run)
	}
	exchange := func(run running, client, value string) {
		t.Helper()
		run.peer.SetReadDeadline(time.Now().Add(time.Second))
		sent := make(chan error, 1)
		go func() { _, err := run.backends[client].Write([]byte(value)); sent <- err }()
		payload := make([]byte, len(value))
		if _, err := io.ReadFull(run.peer, payload); err != nil {
			t.Fatal(err)
		}
		if string(payload) != value {
			t.Fatalf("unexpected responder: %q", payload)
		}
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
	}
	exchange(sessions[0], "a", "before")
	exchange(sessions[1], "a", "stable")
	configuration.Governed[0].PrimaryClientID = "b"
	if err := manager.ConfigureMirrorGroups(configuration); err != nil {
		t.Fatal(err)
	}
	for _, run := range sessions {
		select {
		case <-run.done:
			t.Fatal("reload cancelled existing visitor")
		default:
		}
	}
	// Old primary output must be consumed but never appear on the visitor stream.
	if _, err := sessions[0].backends["a"].Write([]byte("discard")); err != nil {
		t.Fatal(err)
	}
	exchange(sessions[0], "b", "after")
	exchange(sessions[1], "a", "stable")
	configuration.Governed = configuration.Governed[1:]
	if err := manager.ConfigureMirrorGroups(configuration); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sessions[0].done:
	case <-time.After(time.Second):
		t.Fatal("deleted group survived")
	}
	exchange(sessions[1], "a", "stable")
}
