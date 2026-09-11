package vnet

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/acexy/portway/internal/config"
)

var (
	// ErrSourceRejected indicates that a packet source does not own its virtual address.
	ErrSourceRejected = errors.New("VNet packet source rejected")
	// ErrTargetUnavailable indicates that a virtual destination is not configured.
	ErrTargetUnavailable = errors.New("VNet packet target unavailable")
	// ErrFlowRejected indicates that a packet does not belong to an authorized flow.
	ErrFlowRejected = errors.New("VNet flow rejected")
	// ErrFlowCapacity indicates that the bounded flow table is full.
	ErrFlowCapacity = errors.New("VNet flow capacity reached")
)

// DestinationKind identifies the owner of one routed packet.
type DestinationKind uint8

const (
	DestinationServer DestinationKind = iota + 1
	DestinationClient
)

// Destination identifies the VNet endpoint and channel selected for one packet.
type Destination struct {
	Kind         DestinationKind
	ClientID     string
	VirtualIP    netip.Addr
	ChannelIndex uint8
}

type endpointPolicy struct {
	clientID string
	tcp      []config.PortRange
	udp      []config.PortRange
}

type routingPolicy struct {
	serverIP       netip.Addr
	packetChannels uint8
	byIP           map[netip.Addr]endpointPolicy
	byClientID     map[string]netip.Addr
}

type flowKey struct {
	protocol   uint8
	firstIP    [4]byte
	firstPort  uint16
	secondIP   [4]byte
	secondPort uint16
}

type flowState struct {
	serviceIP   netip.Addr
	servicePort uint16
	protocol    uint8
	expiresAt   time.Time
}

// Router owns the bounded authorization state for VNet packet routing.
type Router struct {
	mutex       sync.Mutex
	policy      routingPolicy
	flows       map[flowKey]flowState
	maxFlows    int
	tcpIdle     time.Duration
	udpIdle     time.Duration
	nextCleanup time.Time
}

// NewRouter creates a router from an already validated server configuration.
func NewRouter(configuration config.VirtualNetworkConfig, maxFlows int) (*Router, error) {
	policy, err := buildRoutingPolicy(configuration)
	if err != nil {
		return nil, err
	}
	if maxFlows < 1 {
		return nil, errors.New("VNet maximum flow count must be positive")
	}
	return &Router{
		policy:   policy,
		flows:    make(map[flowKey]flowState),
		maxFlows: maxFlows,
		tcpIdle:  5 * time.Minute,
		udpIdle:  time.Minute,
	}, nil
}

// ApplyPolicy atomically replaces routing policy and removes flows it no longer authorizes.
func (router *Router) ApplyPolicy(configuration config.VirtualNetworkConfig) error {
	policy, err := buildRoutingPolicy(configuration)
	if err != nil {
		return err
	}
	router.mutex.Lock()
	router.policy = policy
	for key, state := range router.flows {
		_, firstExists := policy.byIP[netip.AddrFrom4(key.firstIP)]
		_, secondExists := policy.byIP[netip.AddrFrom4(key.secondIP)]
		if !firstExists || !secondExists ||
			!policy.serviceAllowed(state.serviceIP, state.protocol, state.servicePort) {
			delete(router.flows, key)
		}
	}
	router.mutex.Unlock()
	return nil
}

// RemoveClient removes authorization state involving one disconnected client.
func (router *Router) RemoveClient(clientID string) {
	router.mutex.Lock()
	defer router.mutex.Unlock()
	clientIP, exists := router.policy.byClientID[clientID]
	if !exists {
		return
	}
	address := clientIP.As4()
	for key := range router.flows {
		if key.firstIP == address || key.secondIP == address {
			delete(router.flows, key)
		}
	}
}

// RouteClientPacket validates and routes one packet received from a managed client.
func (router *Router) RouteClientPacket(
	clientID string,
	packet []byte,
	now time.Time,
) (Destination, error) {
	flow, err := ParseIPv4(packet)
	if err != nil {
		return Destination{}, err
	}
	router.mutex.Lock()
	defer router.mutex.Unlock()
	ownedIP, exists := router.policy.byClientID[clientID]
	if !exists || ownedIP != flow.SourceIP {
		return Destination{}, ErrSourceRejected
	}
	return router.routeLocked(flow, now)
}

// RouteServerPacket validates and routes one packet read from the server TUN.
func (router *Router) RouteServerPacket(packet []byte, now time.Time) (Destination, error) {
	flow, err := ParseIPv4(packet)
	if err != nil {
		return Destination{}, err
	}
	router.mutex.Lock()
	defer router.mutex.Unlock()
	if flow.SourceIP != router.policy.serverIP {
		return Destination{}, ErrSourceRejected
	}
	return router.routeLocked(flow, now)
}

func (router *Router) routeLocked(flow Flow, now time.Time) (Destination, error) {
	target, exists := router.policy.byIP[flow.DestinationIP]
	if !exists {
		return Destination{}, ErrTargetUnavailable
	}
	if router.nextCleanup.IsZero() || !now.Before(router.nextCleanup) {
		router.removeExpiredLocked(now)
		router.nextCleanup = now.Add(time.Second)
	}
	key := makeFlowKey(flow)
	state, active := router.flows[key]
	if active && (!now.Before(state.expiresAt) ||
		!router.policy.serviceAllowed(state.serviceIP, state.protocol, state.servicePort)) {
		delete(router.flows, key)
		active = false
	}
	if !active {
		if flow.Protocol == protocolTCP && !flow.IsTCPStart() {
			return Destination{}, ErrFlowRejected
		}
		if !target.allows(flow.Protocol, flow.DestinationPort) {
			return Destination{}, ErrFlowRejected
		}
		if len(router.flows) >= router.maxFlows {
			return Destination{}, ErrFlowCapacity
		}
		state = flowState{
			serviceIP:   flow.DestinationIP,
			servicePort: flow.DestinationPort,
			protocol:    flow.Protocol,
		}
	}
	if flow.Protocol == protocolTCP {
		state.expiresAt = now.Add(router.tcpIdle)
	} else {
		state.expiresAt = now.Add(router.udpIdle)
	}
	if flow.IsTCPReset() {
		delete(router.flows, key)
	} else {
		router.flows[key] = state
	}
	channelIndex, err := ChannelIndex(flow, router.policy.packetChannels)
	if err != nil {
		return Destination{}, err
	}
	destination := Destination{VirtualIP: flow.DestinationIP, ChannelIndex: channelIndex}
	if flow.DestinationIP == router.policy.serverIP {
		destination.Kind = DestinationServer
	} else {
		destination.Kind = DestinationClient
		destination.ClientID = target.clientID
	}
	return destination, nil
}

func (router *Router) removeExpiredLocked(now time.Time) {
	for key, state := range router.flows {
		if !now.Before(state.expiresAt) {
			delete(router.flows, key)
		}
	}
}

func buildRoutingPolicy(configuration config.VirtualNetworkConfig) (routingPolicy, error) {
	serverIP, err := netip.ParseAddr(configuration.ServerIP)
	if err != nil || !serverIP.Is4() || configuration.PacketChannels < 1 || configuration.PacketChannels > 8 {
		return routingPolicy{}, errors.New("invalid VNet routing configuration")
	}
	policy := routingPolicy{
		serverIP:       serverIP,
		packetChannels: uint8(configuration.PacketChannels),
		byIP:           make(map[netip.Addr]endpointPolicy, len(configuration.Nodes)+1),
		byClientID:     make(map[string]netip.Addr, len(configuration.Nodes)),
	}
	policy.byIP[serverIP] = newEndpointPolicy("", configuration.ServerPorts)
	for _, node := range configuration.Nodes {
		address, parseError := netip.ParseAddr(node.IP)
		if parseError != nil || !address.Is4() || node.ClientID == "" {
			return routingPolicy{}, errors.New("invalid VNet node routing configuration")
		}
		if _, duplicate := policy.byIP[address]; duplicate {
			return routingPolicy{}, errors.New("duplicate VNet node address")
		}
		if _, duplicate := policy.byClientID[node.ClientID]; duplicate {
			return routingPolicy{}, errors.New("duplicate VNet client ID")
		}
		policy.byIP[address] = newEndpointPolicy(node.ClientID, node.Ports)
		policy.byClientID[node.ClientID] = address
	}
	return policy, nil
}

func newEndpointPolicy(clientID string, ports config.VNetPortPermissions) endpointPolicy {
	return endpointPolicy{
		clientID: clientID,
		tcp:      append([]config.PortRange(nil), ports.TCP.PortRanges...),
		udp:      append([]config.PortRange(nil), ports.UDP.PortRanges...),
	}
}

func (policy routingPolicy) serviceAllowed(address netip.Addr, protocol uint8, port uint16) bool {
	target, exists := policy.byIP[address]
	return exists && target.allows(protocol, port)
}

func (policy endpointPolicy) allows(protocol uint8, port uint16) bool {
	ranges := policy.udp
	if protocol == protocolTCP {
		ranges = policy.tcp
	} else if protocol != protocolUDP {
		return false
	}
	for _, portRange := range ranges {
		if port >= portRange.Start && port <= portRange.End {
			return true
		}
	}
	return false
}

func makeFlowKey(flow Flow) flowKey {
	firstIP, firstPort := flow.SourceIP, flow.SourcePort
	secondIP, secondPort := flow.DestinationIP, flow.DestinationPort
	if endpointLess(secondIP, secondPort, firstIP, firstPort) {
		firstIP, secondIP = secondIP, firstIP
		firstPort, secondPort = secondPort, firstPort
	}
	return flowKey{
		protocol:   flow.Protocol,
		firstIP:    firstIP.As4(),
		firstPort:  firstPort,
		secondIP:   secondIP.As4(),
		secondPort: secondPort,
	}
}
