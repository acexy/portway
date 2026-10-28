package vnet

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/vnet/internal/flowcontrol"
	"github.com/acexy/portway/internal/vnet/internal/testpacket"
	packetdata "github.com/acexy/portway/internal/vnet/packet"
)

func TestFlowRatePreservesExistingTrafficAndOtherPairs(t *testing.T) {
	configuration := testVNetConfiguration()
	configuration.Nodes = append(configuration.Nodes, config.VNetNodeConfig{ClientID: "client-c", IP: "172.20.0.4"})
	router, err := NewRouter(configuration, 65536)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	for index := range flowcontrol.NewFlowBurst {
		packet := testpacket.IPv4(packetdata.ProtocolTCP, [4]byte{172, 20, 0, 2}, uint16(10000+index), [4]byte{172, 20, 0, 3}, 8080)
		if _, err := router.RouteClientPacket("client-a", packet, now); err != nil {
			t.Fatal(err)
		}
	}
	packet := testpacket.IPv4(packetdata.ProtocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-a", packet, now); !errors.Is(err, ErrFlowRate) {
		t.Fatalf("burst exceeded: %v", err)
	}
	reply := testpacket.IPv4(packetdata.ProtocolTCP, [4]byte{172, 20, 0, 3}, 8080, [4]byte{172, 20, 0, 2}, 10000)
	reply[33] = 0x10
	if _, err := router.RouteClientPacket("client-b", reply, now); err != nil {
		t.Fatalf("existing reply rejected: %v", err)
	}
	other := testpacket.IPv4(packetdata.ProtocolTCP, [4]byte{172, 20, 0, 4}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-c", other, now); err != nil {
		t.Fatalf("other pair starved: %v", err)
	}
	if _, err := router.RouteClientPacket("client-a", packet, now.Add(time.Second)); err != nil {
		t.Fatalf("rate did not recover: %v", err)
	}
	if router.Statistics().RateRejected != 1 {
		t.Fatal("rate rejection not counted")
	}
}

func TestPairCapacityLeavesTargetAvailable(t *testing.T) {
	configuration := testVNetConfiguration()
	configuration.Nodes = append(configuration.Nodes, config.VNetNodeConfig{ClientID: "client-c", IP: "172.20.0.4"})
	router, _ := NewRouter(configuration, 65536)
	now := time.Unix(100, 0)
	for index := range flowcontrol.MaximumPairFlows {
		now = now.Add(10 * time.Millisecond)
		packet := testpacket.IPv4(packetdata.ProtocolTCP, [4]byte{172, 20, 0, 2}, uint16(10000+index), [4]byte{172, 20, 0, 3}, 8080)
		if _, err := router.RouteClientPacket("client-a", packet, now); err != nil {
			t.Fatal(err)
		}
	}
	packet := testpacket.IPv4(packetdata.ProtocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-a", packet, now); !errors.Is(err, ErrFlowCapacity) {
		t.Fatalf("pair cap: %v", err)
	}
	packet = testpacket.IPv4(packetdata.ProtocolTCP, [4]byte{172, 20, 0, 4}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-c", packet, now); err != nil {
		t.Fatalf("target starved: %v", err)
	}
	router.RemoveClient("client-a")
	if count := router.admission.Count(netip.MustParseAddr("172.20.0.2"), netip.MustParseAddr("172.20.0.3")); count != 0 {
		t.Fatal("revocation retained pair quota")
	}
}

func TestNodeQuotaStillBoundsMultipleSources(t *testing.T) {
	configuration := testVNetConfiguration()
	for index := 0; index < 4; index++ {
		configuration.Nodes = append(configuration.Nodes, config.VNetNodeConfig{ClientID: string(rune('c' + index)), IP: netip.AddrFrom4([4]byte{172, 20, 0, byte(4 + index)}).String()})
	}
	router, err := NewRouter(configuration, 65536)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	sources := []string{"client-a", "c", "d", "e"}
	addresses := [][4]byte{{172, 20, 0, 2}, {172, 20, 0, 4}, {172, 20, 0, 5}, {172, 20, 0, 6}}
	for sourceIndex, source := range sources {
		for index := range flowcontrol.MaximumPairFlows {
			now = now.Add(10 * time.Millisecond)
			packet := testpacket.IPv4(packetdata.ProtocolTCP, addresses[sourceIndex], uint16(10000+index), [4]byte{172, 20, 0, 3}, 8080)
			if _, err := router.RouteClientPacket(source, packet, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	packet := testpacket.IPv4(packetdata.ProtocolTCP, [4]byte{172, 20, 0, 7}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("f", packet, now); !errors.Is(err, ErrFlowCapacity) {
		t.Fatalf("node limit bypassed: %v", err)
	}
	router.RemoveClient("client-a")
	if _, err := router.RouteClientPacket("f", packet, now); err != nil {
		t.Fatalf("node quota not released: %v", err)
	}
}

func TestExpiredTCPFlowRequiresNewSYN(t *testing.T) {
	router := testRouter(t)
	packet := testpacket.IPv4(packetdata.ProtocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	now := time.Unix(100, 0)
	if _, err := router.RouteClientPacket("client-a", packet, now); err != nil {
		t.Fatal(err)
	}
	packet[33] = 0x10
	if _, err := router.RouteClientPacket("client-a", packet, now.Add(flowcontrol.TCPFlowIdle)); !errors.Is(err, ErrFlowRejected) {
		t.Fatalf("idle ACK reopened authorization: %v", err)
	}
	packet[33] = 2
	if _, err := router.RouteClientPacket("client-a", packet, now.Add(flowcontrol.TCPFlowIdle)); err != nil {
		t.Fatalf("new SYN failed: %v", err)
	}
}
