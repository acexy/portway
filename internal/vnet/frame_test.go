package vnet

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/acexy/portway/internal/vnet/internal/testpacket"
	packetdata "github.com/acexy/portway/internal/vnet/packet"
)

func TestPacketFrameRejectsMalformedAndTruncatedInput(t *testing.T) {
	for _, test := range []struct {
		name     string
		frame    []byte
		expected error
	}{
		{"boundary_eof", nil, io.EOF},
		{"partial_header", []byte{1, 0}, io.ErrUnexpectedEOF},
		{"missing_payload", []byte{1, 0, 0, 2}, io.ErrUnexpectedEOF},
		{"partial_payload", []byte{1, 0, 0, 2, 1}, io.ErrUnexpectedEOF},
		{"version", []byte{2, 0, 0, 2}, packetdata.ErrInvalidPacket},
		{"reserved", []byte{1, 1, 0, 2}, packetdata.ErrInvalidPacket},
		{"empty", []byte{1, 0, 0, 0}, packetdata.ErrInvalidPacket},
		{"oversized", []byte{1, 0, 255, 255}, packetdata.ErrInvalidPacket},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ReadPacket(bytes.NewReader(test.frame), 1150); !errors.Is(err, test.expected) {
				t.Fatalf("error=%v, want %v", err, test.expected)
			}
		})
	}
}

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
