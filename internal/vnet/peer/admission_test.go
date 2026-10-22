package peer

import (
	"net/netip"
	"testing"
	"time"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/vnet/internal/flowcontrol"
	packetdata "github.com/acexy/portway/internal/vnet/packet"
)

func TestDirectUsesSameAdmissionBudget(t *testing.T) {
	state := &peerOfferState{active: true, offer: protocol.VNetPeerOffer{PeerGeneration: 1, InboundTCP: []protocol.VNetPeerPortRange{{Start: 8080, End: 8080}}}}
	endpoint := &PeerEndpoint{offers: map[uint64]*peerOfferState{1: state}, flows: make(map[[13]byte]peerFlowRoute)}
	flow := packetdata.Flow{Protocol: packetdata.ProtocolTCP, SourceIP: netip.MustParseAddr("172.20.0.2"), DestinationIP: netip.MustParseAddr("172.20.0.3"), DestinationPort: 8080, TCPFlags: 2}
	now := time.Unix(100, 0)
	for index := range flowcontrol.NewFlowBurst {
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
	if count := endpoint.admission.Count(flow.SourceIP, flow.DestinationIP); count != 0 {
		t.Fatal("fallback retained direct quota")
	}
}
