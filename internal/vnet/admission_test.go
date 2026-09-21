package vnet

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
)

func TestFlowRatePreservesExistingTrafficAndOtherPairs(t *testing.T) {
	configuration := testVNetConfiguration()
	configuration.Nodes = append(configuration.Nodes, config.VNetNodeConfig{ClientID: "client-c", IP: "172.20.0.4"})
	router, err := NewRouter(configuration, 65536)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	for index := range newFlowBurst {
		packet := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, uint16(10000+index), [4]byte{172, 20, 0, 3}, 8080)
		if _, err := router.RouteClientPacket("client-a", packet, now); err != nil {
			t.Fatal(err)
		}
	}
	packet := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-a", packet, now); !errors.Is(err, ErrFlowRate) {
		t.Fatalf("burst exceeded: %v", err)
	}
	reply := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 3}, 8080, [4]byte{172, 20, 0, 2}, 10000)
	reply[33] = 0x10
	if _, err := router.RouteClientPacket("client-b", reply, now); err != nil {
		t.Fatalf("existing reply rejected: %v", err)
	}
	other := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 4}, 50000, [4]byte{172, 20, 0, 3}, 8080)
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
	for index := range maximumPairFlows {
		now = now.Add(10 * time.Millisecond)
		packet := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, uint16(10000+index), [4]byte{172, 20, 0, 3}, 8080)
		if _, err := router.RouteClientPacket("client-a", packet, now); err != nil {
			t.Fatal(err)
		}
	}
	packet := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-a", packet, now); !errors.Is(err, ErrFlowCapacity) {
		t.Fatalf("pair cap: %v", err)
	}
	packet = testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 4}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-c", packet, now); err != nil {
		t.Fatalf("target starved: %v", err)
	}
	router.RemoveClient("client-a")
	if state := router.admission.pairs[makeNodePair(netip.MustParseAddr("172.20.0.2"), netip.MustParseAddr("172.20.0.3"))]; state.count != 0 {
		t.Fatal("revocation retained pair quota")
	}
}

func TestDirectUsesSameAdmissionBudget(t *testing.T) {
	state := &peerOfferState{active: true, offer: protocol.VNetPeerOffer{PeerGeneration: 1, InboundTCP: []protocol.VNetPeerPortRange{{Start: 8080, End: 8080}}}}
	endpoint := &PeerEndpoint{offers: map[uint64]*peerOfferState{1: state}, flows: make(map[[13]byte]peerFlowRoute)}
	flow := Flow{Protocol: protocolTCP, SourceIP: netip.MustParseAddr("172.20.0.2"), DestinationIP: netip.MustParseAddr("172.20.0.3"), DestinationPort: 8080, TCPFlags: 2}
	now := time.Unix(100, 0)
	for index := range newFlowBurst {
		flow.SourcePort = uint16(10000 + index)
		if !endpoint.authorizeInbound(state, flow, now) {
			t.Fatal("burst prematurely rejected")
		}
	}
	flow.SourcePort = 50000
	if endpoint.authorizeInbound(state, flow, now) {
		t.Fatal("direct bypassed rate budget")
	}
	if !endpoint.authorizeInbound(state, flow, now.Add(time.Second)) {
		t.Fatal("direct rate did not recover")
	}
	endpoint.relayFlowsLocked(1)
	if state := endpoint.admission.pairs[makeNodePair(flow.SourceIP, flow.DestinationIP)]; state.count != 0 {
		t.Fatal("fallback retained direct quota")
	}
}

func TestReleasedFlowDoesNotResetRateAndBucketsExpire(t *testing.T) {
	var admission flowAdmission
	flow := Flow{SourceIP: netip.MustParseAddr("172.20.0.2"), DestinationIP: netip.MustParseAddr("172.20.0.3")}
	now := time.Unix(100, 0)
	for range newFlowBurst {
		if err := admission.admit(flow, now, 1); err != nil {
			t.Fatal(err)
		}
		admission.release(flow.SourceIP, flow.DestinationIP)
	}
	if err := admission.admit(flow, now, 1); !errors.Is(err, ErrFlowRate) {
		t.Fatalf("release bypassed rate: %v", err)
	}
	flow.DestinationIP = netip.MustParseAddr("172.20.0.4")
	if err := admission.admit(flow, now, 1); !errors.Is(err, ErrFlowCapacity) {
		t.Fatalf("unbounded bucket count: %v", err)
	}
	if err := admission.admit(flow, now.Add(3*time.Second), 1); err != nil {
		t.Fatalf("idle bucket did not expire: %v", err)
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
		for index := range maximumPairFlows {
			now = now.Add(10 * time.Millisecond)
			packet := testIPv4Packet(protocolTCP, addresses[sourceIndex], uint16(10000+index), [4]byte{172, 20, 0, 3}, 8080)
			if _, err := router.RouteClientPacket(source, packet, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	packet := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 7}, 50000, [4]byte{172, 20, 0, 3}, 8080)
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
	packet := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	now := time.Unix(100, 0)
	if _, err := router.RouteClientPacket("client-a", packet, now); err != nil {
		t.Fatal(err)
	}
	packet[33] = 0x10
	if _, err := router.RouteClientPacket("client-a", packet, now.Add(tcpFlowIdle)); !errors.Is(err, ErrFlowRejected) {
		t.Fatalf("idle ACK reopened authorization: %v", err)
	}
	packet[33] = 2
	if _, err := router.RouteClientPacket("client-a", packet, now.Add(tcpFlowIdle)); err != nil {
		t.Fatalf("new SYN failed: %v", err)
	}
}
