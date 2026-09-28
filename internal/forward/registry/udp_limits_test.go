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
)

func udpLimitRegistry(t *testing.T, configuration *config.UDPConfig) (*Registry, map[string]protocol.RequestForwardLink) {
	t.Helper()
	broker := link.NewBroker(context.Background())
	registry := New(broker, func(authentication.Context, protocol.ForwardDeclaration) (bool, bool) {
		return true, true
	}, func() config.UDPConfig { return *configuration })
	t.Cleanup(func() { registry.Close(); broker.Close() })
	requests := make(map[string]protocol.RequestForwardLink)
	for _, clientID := range []string{"one", "two"} {
		results, err := registry.Sync(clientID, "session", control.NewWriter(io.Discard), authentication.Context{}, 10,
			[]protocol.ForwardDeclaration{{Name: "udp", Type: protocol.ForwardTypeUDP, TargetIP: "127.0.0.1", TargetPort: 53}})
		if err != nil {
			t.Fatal(err)
		}
		requests[clientID] = protocol.RequestForwardLink{
			RequestID: "request", Name: "udp", Type: protocol.ForwardTypeUDP, BindingID: results[0].BindingID,
		}
	}
	return registry, requests
}

func TestUDPServerLimitsSpanClientsAndSurviveReload(t *testing.T) {
	configuration := config.DefaultUDPConfig()
	configuration.MaxAssociations = 2
	configuration.MaxAssociationsPerSourceIP = 1
	registry, requests := udpLimitRegistry(t, &configuration)
	first := registry.Offer("one", "session", requests["one"])
	second := registry.Offer("two", "session", requests["two"])
	if first.Error != nil || second.Error != nil {
		t.Fatal("independent clients were incorrectly grouped under a synthetic source IP")
	}
	if offer := registry.Offer("two", "session", requests["two"]); offer.Error == nil {
		t.Fatal("server-wide UDP capacity was exceeded")
	}
	configuration.MaxAssociations = 1
	registry.ApplyPolicy(2, func(authentication.Context, protocol.ForwardDeclaration) bool { return false })
	if stats := registry.udpLimiter.SnapshotStats(); stats.Associations != 2 {
		t.Fatalf("reload reset live reservations: %+v", stats)
	}
	registry.broker.CancelForwardLink("one", "session", first.LinkID)
	if offer := registry.Offer("one", "session", requests["one"]); offer.Error == nil {
		t.Fatal("tightened limit admitted a link before enough capacity was released")
	}
	registry.broker.CancelForwardLink("two", "session", second.LinkID)
	if offer := registry.Offer("one", "session", requests["one"]); offer.Error != nil {
		t.Fatalf("released capacity was not reusable: %+v", offer.Error)
	}
}

func TestUDPServerReservationReleasedOnBrokerRejection(t *testing.T) {
	configuration := config.DefaultUDPConfig()
	registry, requests := udpLimitRegistry(t, &configuration)
	registry.broker.Close()
	if offer := registry.Offer("one", "session", requests["one"]); offer.Error == nil {
		t.Fatal("closed broker admitted a link")
	}
	if stats := registry.udpLimiter.SnapshotStats(); stats.Associations != 0 || stats.PendingAssociations != 0 {
		t.Fatalf("rejected offer retained UDP reservation: %+v", stats)
	}
}

func TestUDPServerReservationTracksBindingLifetime(t *testing.T) {
	for _, fail := range []bool{false, true} {
		configuration := config.DefaultUDPConfig()
		registry, requests := udpLimitRegistry(t, &configuration)
		offer := registry.Offer("one", "session", requests["one"])
		if offer.Error != nil {
			t.Fatal(offer.Error)
		}
		server, peer := net.Pipe()
		defer peer.Close()
		defer server.Close()
		if fail {
			peer.Close()
		}
		done := make(chan error, 1)
		go func() {
			done <- registry.broker.Bind(context.Background(), server, protocol.BindLink{
				ClientID: "one", SessionID: "session", Direction: protocol.LinkDirectionForward,
				ProxyType: protocol.ProxyTypeUDP, BindingID: offer.BindingID, LinkID: offer.LinkID, Ticket: offer.Ticket,
			}, authentication.Context{})
		}()
		if !fail {
			peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := protocol.ReadControl(peer); err != nil {
				t.Fatal(err)
			}
			if stats := registry.udpLimiter.SnapshotStats(); stats.Associations != 1 {
				t.Fatalf("active stream lost its reservation: %+v", stats)
			}
			peer.Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("UDP binding did not terminate")
		}
		if stats := registry.udpLimiter.SnapshotStats(); stats.Associations != 0 || stats.PendingAssociations != 0 {
			t.Fatalf("finished bind retained capacity: %+v", stats)
		}
	}
}
