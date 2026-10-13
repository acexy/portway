package registry

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
)

func TestPolicyNotificationsIsolateSlowSessionAndPreserveOrder(t *testing.T) {
	broker := link.NewBroker(context.Background())
	defer broker.Close()
	registry := New(broker, func(authentication.Context, protocol.ForwardDeclaration) (bool, bool) {
		return true, true
	}, config.DefaultUDPConfig, func(string, string) bool { return true })
	defer registry.Close()
	slowServer, slowClient := net.Pipe()
	defer slowServer.Close()
	defer slowClient.Close()
	fastServer, fastClient := net.Pipe()
	defer fastServer.Close()
	defer fastClient.Close()
	for clientID, connection := range map[string]net.Conn{"slow": slowServer, "fast": fastServer} {
		results, syncError := registry.Sync(clientID, "session", control.NewWriter(connection), authentication.Context{}, 10,
			[]protocol.ForwardDeclaration{{Name: "database", Type: protocol.ForwardTypeTCP, TargetIP: "127.0.0.1", TargetPort: 5432}})
		if syncError != nil {
			t.Fatal(syncError)
		}
		offer := registry.Offer(clientID, "session", protocol.RequestForwardLink{
			RequestID: "request", Name: "database", Type: protocol.ForwardTypeTCP, BindingID: results[0].BindingID,
		})
		if offer.Error != nil {
			t.Fatal(offer.Error)
		}
	}
	notifications := registry.ApplyPolicy(2, func(authentication.Context, protocol.ForwardDeclaration) bool { return true })
	if stats := broker.SnapshotStats(); stats.Pending != 0 || stats.Active != 0 {
		t.Fatalf("local revocation waited for notification: %+v", stats)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { notifications.Deliver(ctx); close(done) }()
	_ = fastClient.SetReadDeadline(time.Now().Add(time.Second))
	for _, expected := range []protocol.MessageType{protocol.MessageForwardBindingRevoked, protocol.MessageForwardBindingActivated} {
		envelope, err := protocol.ReadControl(fastClient)
		if err != nil || envelope.Type != expected {
			t.Fatalf("healthy session notification = %s, error = %v, want %s", envelope.Type, err, expected)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not join blocked notification sender")
	}
	_ = slowClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := slowClient.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("slow session was not closed: %v", err)
	}
}

func TestPolicyNotificationDeadlineClosesAllSlowSessions(t *testing.T) {
	notifications := &PolicyNotifications{sessions: make(map[*control.Writer][]policyNotice)}
	clients := make([]net.Conn, 0, 3)
	for range 3 {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()
		clients = append(clients, client)
		notifications.add(control.NewWriter(server), protocol.MessageForwardBindingRevoked, protocol.ForwardBindingRevoked{})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { notifications.Deliver(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("notification batch exceeded its shared deadline")
	}
	for _, client := range clients {
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("deadline left stale session open: %v", err)
		}
	}
}
