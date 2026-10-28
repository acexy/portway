// Package testpacket builds IPv4 fixtures for VNet regression tests.
package testpacket

import (
	"encoding/binary"
)

func IPv4(
	protocol uint8,
	sourceIP [4]byte,
	sourcePort uint16,
	destinationIP [4]byte,
	destinationPort uint16,
) []byte {
	packet := make([]byte, 24)
	if protocol == 6 {
		packet = make([]byte, 40)
	} else if protocol == 17 {
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
	if protocol == 6 {
		packet[32] = 0x50
		packet[33] = 0x02
	} else if protocol == 17 {
		binary.BigEndian.PutUint16(packet[24:26], uint16(len(packet)-20))
	}
	return packet
}
