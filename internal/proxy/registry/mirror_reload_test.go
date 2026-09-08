package registry

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
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
		manager.AttachAuthenticated(client, client, nil, authentication.Context{Mode: authentication.ModeGoverned, ClientID: client}, 10)
		result := manager.Sync(client, client, "request-"+client, SyncRequest{Revision: 1, Proxies: []protocol.ProxyDeclaration{tcpProxyDeclaration("first", port), tcpProxyDeclaration("second", otherPort)}})
		if result.Status != SyncStatusApplied {
			t.Fatalf("sync: %+v", result)
		}
	}
	type running struct {
		session  *mirrorTCPSession
		peer     net.Conn
		backends map[string]net.Conn
		done     []chan struct{}
	}
	sessions := make([]running, 0, 2)
	for _, p := range []uint16{port, otherPort} {
		visitor, peer := net.Pipe()
		ctx, cancel := context.WithCancel(manager.context)
		manager.mutex.Lock()
		group := manager.tcpMirrorGroups[p]
		manager.mutex.Unlock()
		session := &mirrorTCPSession{context: ctx, cancel: cancel, manager: manager, group: group, visitor: visitor, members: make(map[string]*mirrorTCPMember), workers: make(map[string]*mirrorTCPWorker)}
		if !manager.addMirrorTCPSession(group, session) {
			t.Fatal("session rejected")
		}
		stop := context.AfterFunc(ctx, func() { visitor.Close() })
		t.Cleanup(func() {
			cancel()
			stop()
			visitor.Close()
			peer.Close()
			manager.removeMirrorTCPSession(group, session)
		})
		run := running{session: session, peer: peer, backends: make(map[string]net.Conn)}
		for _, client := range []string{"a", "b"} {
			stream, backend := net.Pipe()
			member := &mirrorTCPMember{connection: stream, target: mirrorTCPTarget{target: link.Target{ClientID: client}}}
			session.members[client] = member
			done := make(chan struct{})
			go func() { defer close(done); session.copyResponse(member) }()
			t.Cleanup(func() { stream.Close(); backend.Close(); <-done })
			run.backends[client] = backend
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
		if run.session.context.Err() != nil {
			t.Fatal("reload cancelled existing visitor")
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
	if sessions[0].session.context.Err() == nil {
		t.Fatal("deleted group survived")
	}
	exchange(sessions[1], "a", "stable")
}
