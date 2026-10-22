package packet

import (
	"net/netip"
	"testing"
)

func TestKeyPreservesBidirectionalFlowIdentity(t *testing.T) {
	for _, sameAddress := range []bool{false, true} {
		flow := Flow{
			Protocol: ProtocolTCP, SourceIP: netip.MustParseAddr("172.20.0.2"),
			DestinationIP: netip.MustParseAddr("172.20.0.3"), SourcePort: 50000,
			DestinationPort: 8080, TCPFlags: 2,
		}
		if sameAddress {
			flow.DestinationIP = flow.SourceIP
		}
		reply := flow
		reply.SourceIP, reply.DestinationIP = flow.DestinationIP, flow.SourceIP
		reply.SourcePort, reply.DestinationPort = flow.DestinationPort, flow.SourcePort
		reply.TCPFlags = 0x10
		if MakeKey(flow) != MakeKey(reply) {
			t.Fatalf("reply changed flow identity (same address: %v)", sameAddress)
		}
		other := flow
		other.Protocol = ProtocolUDP
		if MakeKey(flow) == MakeKey(other) {
			t.Fatal("different protocols share a flow key")
		}
		other = flow
		other.SourcePort++
		if MakeKey(flow) == MakeKey(other) {
			t.Fatal("different ports share a flow key")
		}
	}
}
