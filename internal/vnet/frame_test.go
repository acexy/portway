package vnet

import (
	"bytes"
	"errors"
	"testing"

	"github.com/acexy/portway/internal/vnet/internal/testpacket"
	packetdata "github.com/acexy/portway/internal/vnet/packet"
)

func TestPacketFrameRoundTripAndLimits(t *testing.T) {
	packet := testpacket.IPv4(packetdata.ProtocolUDP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 53)
	var encoded bytes.Buffer
	if err := WritePacket(&encoded, packet, 1280); err != nil {
		t.Fatalf("write packet: %v", err)
	}
	decoded, err := ReadPacket(&encoded, 1280)
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	if !bytes.Equal(decoded, packet) {
		t.Fatal("packet frame changed payload")
	}
	if err := WritePacket(&encoded, make([]byte, 1281), 1280); !errors.Is(err, packetdata.ErrInvalidPacket) {
		t.Fatalf("expected MTU rejection, got %v", err)
	}
}
