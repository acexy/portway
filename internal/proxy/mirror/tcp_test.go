package mirror

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/acexy/portway/internal/link"
)

type testTargetGuard struct {
	sync.Mutex
	targets map[string]link.Target
}

func (guard *testTargetGuard) IsCurrent(target link.Target) bool {
	current, exists := guard.targets[target.ClientID]
	return exists && current.SessionID == target.SessionID &&
		current.BindingID == target.BindingID && current.Writer == target.Writer
}

func waitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for mirror task")
	}
}

func TestTCPSessionRejectsTargetRevokedDuringOpen(t *testing.T) {
	target := link.Target{ClientID: "client", SessionID: "session", BindingID: "binding"}
	guard := &testTargetGuard{targets: map[string]link.Target{target.ClientID: target}}
	visitor, peer := net.Pipe()
	defer peer.Close()
	stream, backend := net.Pipe()
	defer backend.Close()
	opened := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	session := NewTCPSession(context.Background(), visitor, guard,
		func(ctx context.Context, _ link.Target) (net.Conn, error) {
			close(opened)
			select {
			case <-release:
				return stream, nil
			case <-ctx.Done():
				stream.Close()
				return nil, ctx.Err()
			}
		})
	defer session.Cancel()
	done := make(chan struct{})
	go func() { defer close(done); session.Serve([]link.Target{target}) }()
	t.Cleanup(func() { session.Cancel(); waitSignal(t, done) })
	waitSignal(t, opened)
	// Acquiring the guard here also verifies that opening a stream holds no lock.
	guard.Lock()
	delete(guard.targets, target.ClientID)
	guard.Unlock()
	unblock()
	if err := backend.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("revoked stream was not closed: %v", err)
	}
	if members := session.snapshotMembers(); len(members) != 0 {
		t.Fatalf("revoked stream was published: %d members", len(members))
	}
	session.Cancel()
	waitSignal(t, done)
}

func TestTCPSessionReplacementWaitsForPreviousGeneration(t *testing.T) {
	previous := link.Target{ClientID: "client", SessionID: "old", BindingID: "old"}
	current := link.Target{ClientID: "client", SessionID: "new", BindingID: "new"}
	guard := &testTargetGuard{targets: map[string]link.Target{previous.ClientID: previous}}
	visitor, peer := net.Pipe()
	defer peer.Close()
	oldOpened := make(chan struct{})
	oldCancelled := make(chan struct{})
	newOpened := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	session := NewTCPSession(context.Background(), visitor, guard,
		func(ctx context.Context, target link.Target) (net.Conn, error) {
			if target.SessionID == previous.SessionID {
				close(oldOpened)
				<-ctx.Done()
				close(oldCancelled)
				<-release
			} else {
				close(newOpened)
				<-ctx.Done()
			}
			return nil, ctx.Err()
		})
	defer session.Cancel()
	done := make(chan struct{})
	go func() { defer close(done); session.Serve([]link.Target{previous}) }()
	t.Cleanup(func() { unblock(); session.Cancel(); waitSignal(t, done) })
	waitSignal(t, oldOpened)
	guard.Lock()
	guard.targets[current.ClientID] = current
	guard.Unlock()
	session.AddTarget(current)
	waitSignal(t, oldCancelled)
	select {
	case <-newOpened:
		t.Fatal("replacement opened before the old task released its resources")
	default:
	}
	unblock()
	waitSignal(t, newOpened)
	session.Cancel()
	waitSignal(t, done)
}

func TestTCPSessionPrimarySwitchPreservesStreamsAndCancellation(t *testing.T) {
	targets := []link.Target{
		{ClientID: "a", SessionID: "a", BindingID: "a"},
		{ClientID: "b", SessionID: "b", BindingID: "b"},
	}
	guard := &testTargetGuard{targets: map[string]link.Target{"a": targets[0], "b": targets[1]}}
	visitor, peer := net.Pipe()
	defer peer.Close()
	streams := make(map[string]net.Conn)
	backends := make(map[string]net.Conn)
	for _, target := range targets {
		stream, backend := net.Pipe()
		streams[target.ClientID] = stream
		backends[target.ClientID] = backend
		defer backend.Close()
	}
	session := NewTCPSession(context.Background(), visitor, guard,
		func(_ context.Context, target link.Target) (net.Conn, error) { return streams[target.ClientID], nil })
	defer session.Cancel()
	session.SetPrimary("a")
	done := make(chan struct{})
	go func() { defer close(done); session.Serve(targets) }()
	t.Cleanup(func() { session.Cancel(); waitSignal(t, done) })
	for _, target := range targets {
		waitSignal(t, session.AddTarget(target))
	}
	exchange := func(client, message string) {
		t.Helper()
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		sent := make(chan error, 1)
		go func() { _, err := backends[client].Write([]byte(message)); sent <- err }()
		payload := make([]byte, len(message))
		if _, err := io.ReadFull(peer, payload); err != nil || string(payload) != message {
			t.Fatalf("response = %q, error = %v", payload, err)
		}
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
	}
	exchange("a", "before")
	session.SetPrimary("b")
	if err := backends["a"].SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := backends["a"].Write([]byte("discard")); err != nil {
		t.Fatalf("old Primary response was not consumed: %v", err)
	}
	exchange("b", "after")
	session.Cancel()
	waitSignal(t, done)
	for client, backend := range backends {
		if _, err := backend.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("member %s was not closed: %v", client, err)
		}
	}
}
