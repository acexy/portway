package registry

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/session"
)

func TestForwardOfferFollowsSessionSuspensionAndRecovery(t *testing.T) {
	broker := link.NewBroker(context.Background())
	defer broker.Close()
	sessions := session.NewRegistry()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	now := time.Now()
	sessions.Register("client", "", "session", server, now)
	sessions.Activate("client", "session", now)
	registry := New(broker, func(authentication.Context, protocol.ForwardDeclaration) (bool, bool) {
		return true, true
	}, config.DefaultUDPConfig, sessions.Active)
	defer registry.Close()
	results, syncError := registry.Sync("client", "session", nil, authentication.Context{}, 10,
		[]protocol.ForwardDeclaration{{Name: "database", Type: protocol.ForwardTypeTCP, TargetIP: "127.0.0.1", TargetPort: 5432}})
	if syncError != nil {
		t.Fatal(syncError)
	}
	request := protocol.RequestForwardLink{RequestID: "request", Name: "database", Type: protocol.ForwardTypeTCP, BindingID: results[0].BindingID}
	if offer := registry.Offer("client", "session", request); offer.Error != nil {
		t.Fatalf("active session rejected: %+v", offer.Error)
	}
	sessions.Sweep(now.Add(time.Second), time.Second, time.Minute)
	broker.CancelSession("client", "session")
	if offer := registry.Offer("client", "session", request); offer.Error == nil || offer.Error.Code != protocol.ForwardErrorSessionInactive {
		t.Fatalf("suspended session offer = %+v", offer)
	}
	if stats := broker.SnapshotStats(); stats.Pending != 0 || stats.Active != 0 {
		t.Fatalf("suspended session retained links: %+v", stats)
	}
	accepted, recovered := sessions.Heartbeat("client", "session", 1, now.Add(2*time.Second))
	if !accepted || !recovered {
		t.Fatal("heartbeat did not recover session")
	}
	if offer := registry.Offer("client", "session", request); offer.Error != nil {
		t.Fatalf("recovered session rejected: %+v", offer.Error)
	}
}

func TestForwardOfferCancelsReservationWhenSuspensionWinsPublication(t *testing.T) {
	broker := link.NewBroker(context.Background())
	defer broker.Close()
	checks := 0
	registry := New(broker, func(authentication.Context, protocol.ForwardDeclaration) (bool, bool) {
		return true, true
	}, config.DefaultUDPConfig, func(clientID, sessionID string) bool {
		checks++
		if checks == 1 {
			// Model a Sweep that cancels the old set before Offer reserves a ticket.
			broker.CancelSession(clientID, sessionID)
			return true
		}
		return false
	})
	defer registry.Close()
	results, syncError := registry.Sync("client", "session", nil, authentication.Context{}, 10,
		[]protocol.ForwardDeclaration{{Name: "dns", Type: protocol.ForwardTypeUDP, TargetIP: "127.0.0.1", TargetPort: 53}})
	if syncError != nil {
		t.Fatal(syncError)
	}
	offer := registry.Offer("client", "session", protocol.RequestForwardLink{
		RequestID: "request", Name: "dns", Type: protocol.ForwardTypeUDP, BindingID: results[0].BindingID,
	})
	if offer.Error == nil || offer.Error.Code != protocol.ForwardErrorSessionInactive {
		t.Fatalf("racing suspension offer = %+v", offer)
	}
	if stats := broker.SnapshotStats(); stats.Pending != 0 || stats.Active != 0 {
		t.Fatalf("racing suspension leaked ticket: %+v", stats)
	}
	if stats := registry.udpLimiter.SnapshotStats(); stats.Associations != 0 || stats.PendingAssociations != 0 {
		t.Fatalf("racing suspension leaked UDP reservation: %+v", stats)
	}
}

func TestForwardTargetFactoryRejectsSuspendedSession(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	broker := link.NewBroker(context.Background())
	defer broker.Close()
	active := true
	registry := New(broker, func(authentication.Context, protocol.ForwardDeclaration) (bool, bool) {
		return true, true
	}, config.DefaultUDPConfig, func(string, string) bool { return active })
	defer registry.Close()
	_, syncError := registry.Sync("client", "session", nil, authentication.Context{}, 10,
		[]protocol.ForwardDeclaration{{Name: "database", Type: protocol.ForwardTypeTCP, TargetIP: "127.0.0.1", TargetPort: uint16(target.Addr().(*net.TCPAddr).Port)}})
	if syncError != nil {
		t.Fatal(syncError)
	}
	factory := registry.handlerFactory(*registry.bindings[bindingKey("client", "session", "database")])
	active = false
	handler, cleanup, err := factory(context.Background())
	if cleanup != nil {
		cleanup()
	}
	if err == nil || handler != nil {
		t.Fatal("suspended session prepared a target connection")
	}
}
