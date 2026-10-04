package udp

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
)

func TestAssociationCopiesOnlyAdmittedPayload(t *testing.T) {
	configuration := config.DefaultUDPConfig()
	configuration.MaxQueuedDatagramsPerAssociation = 1
	limiter := NewLimiter(configuration)
	lease, ok := limiter.Acquire("client", "proxy", netip.MustParseAddr("192.0.2.1"), time.Now())
	if !ok {
		t.Fatal("lease rejected")
	}
	defer lease.Close()
	association := &association{lease: lease, queue: make(chan []byte, 1)}
	payload := []byte("original")
	if !association.enqueue(payload) {
		t.Fatal("first packet rejected")
	}
	payload[0] = 'X'
	if allocations := testing.AllocsPerRun(100, func() { association.enqueue(payload) }); allocations != 0 {
		t.Fatalf("full queue allocated: %v", allocations)
	}
	queued := <-association.queue
	if string(queued) != "original" {
		t.Fatalf("borrowed payload retained: %q", queued)
	}
	lease.ReleaseQueue(len(queued))
}

func TestAssociationRetainsCapacityUntilTasksFinish(t *testing.T) {
	configuration := config.DefaultUDPConfig()
	limiter := NewLimiter(configuration)
	source := netip.MustParseAddrPort("192.0.2.1:1234")
	lease, ok := limiter.Acquire("client", "proxy", source.Addr(), time.Now())
	if !ok {
		t.Fatal("lease rejected")
	}
	binding := &Binding{context: context.Background(), configuration: configuration,
		associations: make(map[netip.AddrPort]*association)}
	current := newAssociation(binding, source, link.Target{}, lease)
	binding.waitGroup.Add(1)
	binding.associations[source] = current
	current.Close()
	if limiter.SnapshotStats().Associations != 1 {
		t.Fatal("cancellation returned live task capacity")
	}
	current.finish()
	if limiter.SnapshotStats().Associations != 1 {
		t.Fatal("pending control write lost its capacity")
	}
	current.complete(true)
	binding.waitGroup.Wait()
	if limiter.SnapshotStats().Associations != 0 {
		t.Fatal("finished task retained capacity")
	}
}

func TestBindingCloseCompletesAfterBindResponseFailure(t *testing.T) {
	broker := link.NewBroker(context.Background())
	defer broker.Close()
	serverControl, clientControl := net.Pipe()
	defer serverControl.Close()
	defer clientControl.Close()
	configuration := config.DefaultUDPConfig()
	limiter := NewLimiter(configuration)
	target := link.Target{
		ClientID: "client", SessionID: "session", BindingName: "proxy",
		BindingID: "binding", TrafficType: link.TrafficTypeUDP,
		Writer: control.NewWriter(serverControl),
	}
	binding := NewBinding(context.Background(), configuration, nil, broker, limiter, nil,
		func() (link.Target, error) { return target, nil })
	binding.HandleDatagram(netip.MustParseAddrPort("192.0.2.1:1234"), []byte("queued"))
	clientControl.SetReadDeadline(time.Now().Add(time.Second))
	envelope, err := protocol.ReadControl(clientControl)
	if err != nil {
		t.Fatal(err)
	}
	var offer protocol.OpenLink
	if err := protocol.DecodePayload(envelope, &offer); err != nil {
		t.Fatal(err)
	}
	serverData, clientData := net.Pipe()
	defer serverData.Close()
	clientData.Close()
	err = broker.Bind(context.Background(), serverData, protocol.BindLink{
		ClientID: target.ClientID, SessionID: target.SessionID,
		ProxyType: protocol.ProxyTypeUDP, BindingID: target.BindingID,
		LinkID: offer.LinkID, Ticket: offer.Ticket,
	}, authentication.Context{})
	if err == nil {
		t.Fatal("closed data stream was accepted")
	}
	done := make(chan struct{})
	go func() { binding.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("binding shutdown waited forever for an undelivered stream")
	}
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	if limiter.total != 0 || limiter.pending != 0 || limiter.queuedBytes != 0 {
		t.Fatalf("association retained capacity: total=%d pending=%d queued=%d",
			limiter.total, limiter.pending, limiter.queuedBytes)
	}
}
