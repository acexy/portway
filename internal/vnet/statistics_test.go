package vnet

import (
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/vnet/internal/testpacket"
	packetdata "github.com/acexy/portway/internal/vnet/packet"
)

func TestPoolStatisticsExcludeUnpublishedChannels(t *testing.T) {
	broker := NewPoolBroker()
	broker.pending["pending"] = &pendingPool{channels: make([]pendingChannel, 3)}
	broker.active["active"] = &Pool{channels: make([]net.Conn, 2)}
	if stats := broker.Statistics(); stats.Pending != 1 || stats.Active != 1 || stats.ActiveChannels != 2 {
		t.Fatalf("unexpected pool counts: %+v", stats)
	}
}

func TestRouterStatisticsRetainRejectionsAcrossPolicyAndCleanup(t *testing.T) {
	router := testRouter(t)
	packet := testpacket.IPv4(packetdata.ProtocolTCP, [4]byte{172, 20, 0, 9}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-a", packet, time.Now()); err == nil {
		t.Fatal("spoofed packet was accepted")
	}
	before := router.Statistics()
	if before.PolicyRejected != 1 || before.Active != 0 {
		t.Fatalf("rejection snapshot: %+v", before)
	}
	router.RemoveClient("client-a")
	// Disabling the policy must not reset cumulative rejection counters.
	if err := router.ApplyPolicy(config.DefaultServer().VirtualNetwork); err != nil {
		t.Fatal(err)
	}
	if after := router.Statistics(); after.PolicyRejected != before.PolicyRejected {
		t.Fatalf("policy update reset cumulative statistics: %+v", after)
	}
}
