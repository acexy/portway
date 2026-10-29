package udp

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/link"
)

func TestEndpointTrafficCountsCompletedFrames(t *testing.T) {
	configuration := config.DefaultUDPConfig()
	endpoint := &Endpoint{}
	binding := &Binding{context: context.Background(), configuration: configuration, endpoint: endpoint,
		associations: make(map[netip.AddrPort]*association)}
	source := netip.MustParseAddrPort("192.0.2.1:1234")
	limiter := NewLimiter(configuration)
	lease, accepted := limiter.Acquire("client", "proxy", source.Addr(), time.Now())
	if !accepted {
		t.Fatal("lease rejected")
	}
	current := newAssociation(binding, source, link.Target{}, lease)
	binding.waitGroup.Add(1)
	current.complete(true)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if !current.enqueue([]byte("up")) {
		t.Fatal("packet rejected")
	}
	done := make(chan error, 1)
	go func() { done <- current.forward(context.Background(), local) }()
	packet, err := ReadDatagram(peer, configuration.MaxDatagramSize)
	if err != nil || string(packet) != "up" {
		t.Fatalf("packet=%q error=%v", packet, err)
	}
	if err := WriteDatagram(peer, []byte("down"), configuration.MaxDatagramSize); err != nil {
		t.Fatal(err)
	}
	peer.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("forward did not stop")
	}
	fields, _ := endpoint.traffic.drain()
	for name, expected := range map[string]uint64{"uplink_datagrams": 1, "uplink_bytes": 2, "downlink_datagrams": 1, "downlink_bytes": 4} {
		if fields[name] != expected {
			t.Fatalf("%s=%v, want %d", name, fields[name], expected)
		}
	}
	if limiter.SnapshotStats().Associations != 0 {
		t.Fatal("completed forwarding retained lease")
	}
}

func TestEndpointTrafficCountsAdmissionQueueAndExpiry(t *testing.T) {
	configuration := config.DefaultUDPConfig()
	configuration.MaxPendingAssociations = 1
	configuration.MaxQueuedDatagramsPerAssociation = 1
	endpoint := &Endpoint{}
	broker := link.NewBroker(context.Background())
	defer broker.Close()
	limiter := NewLimiter(configuration)
	binding := NewBinding(context.Background(), configuration, endpoint, broker, limiter, nil,
		func() (link.Target, error) {
			return link.Target{ClientID: "client", SessionID: "session", BindingName: "proxy", BindingID: "binding", Writer: control.NewWriter(io.Discard)}, nil
		})
	defer binding.Close()
	source := netip.MustParseAddrPort("192.0.2.1:1234")
	binding.HandleDatagram(source, []byte("queued"))
	binding.HandleDatagram(source, []byte("overflow"))
	binding.HandleDatagram(netip.MustParseAddrPort("192.0.2.2:1234"), []byte("rejected"))
	binding.mutex.Lock()
	current := binding.associations[source]
	binding.mutex.Unlock()
	if current == nil {
		t.Fatal("association was not published")
	}
	current.closeIfIdle(time.Now().Add(time.Hour))
	current.closeIfIdle(time.Now().Add(time.Hour))
	current.recordWriteTimeout(context.Canceled)
	current.recordWriteTimeout(context.DeadlineExceeded)
	fields, active := endpoint.traffic.drain()
	if !active {
		t.Fatal("events did not activate summary")
	}
	for _, name := range []string{"created_associations", "rejected_associations", "expired_associations", "queue_dropped_datagrams", "write_timeouts"} {
		if fields[name] != uint64(1) {
			t.Fatalf("%s=%v, want 1", name, fields[name])
		}
	}
	if _, active := endpoint.traffic.drain(); active {
		t.Fatal("interval drain retained old events")
	}
	binding.Close()
	if stats := limiter.SnapshotStats(); stats.Associations != 0 || stats.PendingAssociations != 0 || stats.QueuedBytes != 0 {
		t.Fatalf("statistics changed lease ownership: %+v", stats)
	}
}
