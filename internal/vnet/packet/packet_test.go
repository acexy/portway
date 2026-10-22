package packet

import (
	"errors"
	"testing"

	"github.com/acexy/portway/internal/vnet/internal/testpacket"
)

func TestParseIPv4AndChannelIndexAreDirectionIndependent(t *testing.T) {
	forward := testpacket.IPv4(ProtocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 443)
	reverse := testpacket.IPv4(ProtocolTCP, [4]byte{172, 20, 0, 3}, 443, [4]byte{172, 20, 0, 2}, 50000)
	forwardFlow, err := ParseIPv4(forward)
	if err != nil {
		t.Fatalf("parse forward packet: %v", err)
	}
	reverseFlow, err := ParseIPv4(reverse)
	if err != nil {
		t.Fatalf("parse reverse packet: %v", err)
	}
	forwardIndex, err := ChannelIndex(forwardFlow, 4)
	if err != nil {
		t.Fatalf("select forward channel: %v", err)
	}
	reverseIndex, err := ChannelIndex(reverseFlow, 4)
	if err != nil {
		t.Fatalf("select reverse channel: %v", err)
	}
	if forwardIndex != reverseIndex {
		t.Fatalf("direction changed channel index: %d != %d", forwardIndex, reverseIndex)
	}
}

func TestParseIPv4RejectsFragmentsAndUnsupportedProtocols(t *testing.T) {
	fragment := testpacket.IPv4(ProtocolUDP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 53)
	fragment[6] = 0x20
	if _, err := ParseIPv4(fragment); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("expected fragment rejection, got %v", err)
	}
	unsupported := testpacket.IPv4(1, [4]byte{172, 20, 0, 2}, 0, [4]byte{172, 20, 0, 3}, 0)
	if _, err := ParseIPv4(unsupported); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("expected protocol rejection, got %v", err)
	}
}
