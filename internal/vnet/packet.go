// Package vnet validates and routes packets for the governed virtual network.
package vnet

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	ipv4MinimumHeaderLength = 20
	protocolTCP             = 6
	protocolUDP             = 17
)

// ErrInvalidPacket identifies malformed or unsupported VNet input.
var ErrInvalidPacket = errors.New("invalid VNet packet")

// Flow identifies the direction-independent TCP or UDP five-tuple of one packet.
type Flow struct {
	Protocol        uint8
	SourceIP        netip.Addr
	SourcePort      uint16
	DestinationIP   netip.Addr
	DestinationPort uint16
	TCPFlags        uint8
}

// IsTCPStart reports whether the packet starts a new TCP flow.
func (flow Flow) IsTCPStart() bool {
	return flow.Protocol == protocolTCP && flow.TCPFlags&0x02 != 0 && flow.TCPFlags&0x10 == 0
}

// IsTCPReset reports whether the packet terminates a TCP flow immediately.
func (flow Flow) IsTCPReset() bool {
	return flow.Protocol == protocolTCP && flow.TCPFlags&0x04 != 0
}

// ParseIPv4 validates one complete, unfragmented TCP or UDP IPv4 packet.
func ParseIPv4(packet []byte) (Flow, error) {
	if len(packet) < ipv4MinimumHeaderLength || packet[0]>>4 != 4 {
		return Flow{}, fmt.Errorf("%w: invalid IPv4 header", ErrInvalidPacket)
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < ipv4MinimumHeaderLength || headerLength > len(packet) {
		return Flow{}, fmt.Errorf("%w: invalid IPv4 header length", ErrInvalidPacket)
	}
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength != len(packet) {
		return Flow{}, fmt.Errorf("%w: IPv4 total length mismatch", ErrInvalidPacket)
	}
	fragment := binary.BigEndian.Uint16(packet[6:8])
	if fragment&0x3fff != 0 {
		return Flow{}, fmt.Errorf("%w: IPv4 fragmentation is unsupported", ErrInvalidPacket)
	}
	protocol := packet[9]
	if protocol != protocolTCP && protocol != protocolUDP {
		return Flow{}, fmt.Errorf("%w: unsupported IPv4 protocol", ErrInvalidPacket)
	}
	minimumTransportLength := 8
	if protocol == protocolTCP {
		minimumTransportLength = 20
	}
	if totalLength < headerLength+minimumTransportLength {
		return Flow{}, fmt.Errorf("%w: truncated transport header", ErrInvalidPacket)
	}
	flow := Flow{
		Protocol:        protocol,
		SourceIP:        netip.AddrFrom4([4]byte(packet[12:16])),
		SourcePort:      binary.BigEndian.Uint16(packet[headerLength : headerLength+2]),
		DestinationIP:   netip.AddrFrom4([4]byte(packet[16:20])),
		DestinationPort: binary.BigEndian.Uint16(packet[headerLength+2 : headerLength+4]),
	}
	if flow.SourcePort == 0 || flow.DestinationPort == 0 {
		return Flow{}, fmt.Errorf("%w: zero transport port", ErrInvalidPacket)
	}
	if protocol == protocolTCP {
		tcpHeaderLength := int(packet[headerLength+12]>>4) * 4
		if tcpHeaderLength < 20 || headerLength+tcpHeaderLength > totalLength {
			return Flow{}, fmt.Errorf("%w: invalid TCP header length", ErrInvalidPacket)
		}
		flow.TCPFlags = packet[headerLength+13]
	} else {
		udpLength := int(binary.BigEndian.Uint16(packet[headerLength+4 : headerLength+6]))
		if udpLength < 8 || headerLength+udpLength != totalLength {
			return Flow{}, fmt.Errorf("%w: invalid UDP length", ErrInvalidPacket)
		}
	}
	return flow, nil
}

// ChannelIndex maps both directions of one flow to the same channel index.
func ChannelIndex(flow Flow, channelCount uint8) (uint8, error) {
	if channelCount == 0 || channelCount > 8 {
		return 0, errors.New("VNet channel count must be between 1 and 8")
	}
	if !flow.SourceIP.Is4() || !flow.DestinationIP.Is4() ||
		(flow.Protocol != protocolTCP && flow.Protocol != protocolUDP) {
		return 0, errors.New("VNet flow must contain IPv4 TCP or UDP endpoints")
	}
	firstIP, firstPort := flow.SourceIP, flow.SourcePort
	secondIP, secondPort := flow.DestinationIP, flow.DestinationPort
	if endpointLess(secondIP, secondPort, firstIP, firstPort) {
		firstIP, secondIP = secondIP, firstIP
		firstPort, secondPort = secondPort, firstPort
	}
	first := firstIP.As4()
	second := secondIP.As4()
	encoded := [13]byte{flow.Protocol}
	copy(encoded[1:5], first[:])
	binary.BigEndian.PutUint16(encoded[5:7], firstPort)
	copy(encoded[7:11], second[:])
	binary.BigEndian.PutUint16(encoded[11:13], secondPort)
	digest := sha256.Sum256(encoded[:])
	return uint8(binary.BigEndian.Uint64(digest[:8]) % uint64(channelCount)), nil
}

func endpointLess(leftIP netip.Addr, leftPort uint16, rightIP netip.Addr, rightPort uint16) bool {
	comparison := leftIP.Compare(rightIP)
	return comparison < 0 || comparison == 0 && leftPort < rightPort
}
