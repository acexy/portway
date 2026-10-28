package packet

// Key identifies a flow independently of packet direction.
type Key struct {
	Protocol   uint8
	FirstIP    [4]byte
	FirstPort  uint16
	SecondIP   [4]byte
	SecondPort uint16
}

// MakeKey canonicalizes endpoints of an already validated IPv4 flow.
func MakeKey(flow Flow) Key {
	firstIP, firstPort := flow.SourceIP, flow.SourcePort
	secondIP, secondPort := flow.DestinationIP, flow.DestinationPort
	if endpointLess(secondIP, secondPort, firstIP, firstPort) {
		firstIP, secondIP = secondIP, firstIP
		firstPort, secondPort = secondPort, firstPort
	}
	return Key{
		Protocol:   flow.Protocol,
		FirstIP:    firstIP.As4(),
		FirstPort:  firstPort,
		SecondIP:   secondIP.As4(),
		SecondPort: secondPort,
	}
}
