package vnet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseIPv4AndChannelIndexAreDirectionIndependent(t *testing.T) {
	forward := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 443)
	reverse := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 3}, 443, [4]byte{172, 20, 0, 2}, 50000)
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
	fragment := testIPv4Packet(protocolUDP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 53)
	fragment[6] = 0x20
	if _, err := ParseIPv4(fragment); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("expected fragment rejection, got %v", err)
	}
	unsupported := testIPv4Packet(1, [4]byte{172, 20, 0, 2}, 0, [4]byte{172, 20, 0, 3}, 0)
	if _, err := ParseIPv4(unsupported); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("expected protocol rejection, got %v", err)
	}
}

func TestPacketFrameRoundTripAndLimits(t *testing.T) {
	packet := testIPv4Packet(protocolUDP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 53)
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
	if err := WritePacket(&encoded, make([]byte, 1281), 1280); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("expected MTU rejection, got %v", err)
	}
}

func testIPv4Packet(
	protocol uint8,
	sourceIP [4]byte,
	sourcePort uint16,
	destinationIP [4]byte,
	destinationPort uint16,
) []byte {
	packet := make([]byte, 24)
	if protocol == protocolTCP {
		packet = make([]byte, 40)
	} else if protocol == protocolUDP {
		packet = make([]byte, 28)
	}
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], sourceIP[:])
	copy(packet[16:20], destinationIP[:])
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	if protocol == protocolTCP {
		packet[32] = 0x50
		packet[33] = 0x02
	} else if protocol == protocolUDP {
		binary.BigEndian.PutUint16(packet[24:26], uint16(len(packet)-20))
	}
	return packet
}
