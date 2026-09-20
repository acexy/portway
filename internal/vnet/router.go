package vnet

import (
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/acexy/portway/internal/config"
)

const routerCleanupBatchSize = 256
const routerMaximumNodeFlows = 4096

var (
	// ErrSourceRejected indicates that a packet source does not own its virtual address.
	ErrSourceRejected = errors.New("VNet packet source rejected")
	// ErrTargetUnavailable indicates that a virtual destination is not configured.
	ErrTargetUnavailable = errors.New("VNet packet target unavailable")
	// ErrFlowRejected indicates that a packet does not belong to an authorized flow.
	ErrFlowRejected = errors.New("VNet flow rejected")
	// ErrFlowCapacity indicates that the bounded flow table is full.
	ErrFlowCapacity = errors.New("VNet flow capacity reached")
	// ErrFlowRate indicates that a node pair exhausted its new-flow budget.
	ErrFlowRate = errors.New("VNet new flow rate reached")
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
	mutex               sync.Mutex
	admission           flowAdmission
	capacityRejected    uint64
	rateRejected        uint64
	policyRejected      uint64
	policy              routingPolicy
	flows               map[flowKey]flowState
	nodeFlows           map[netip.Addr]int
	maxFlows            int
	tcpIdle             time.Duration
	udpIdle             time.Duration
	nextCleanup         time.Time
	nextCapacityCleanup time.Time
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
		policy:    policy,
		flows:     make(map[flowKey]flowState),
		nodeFlows: make(map[netip.Addr]int),
		maxFlows:  maxFlows,
		tcpIdle:   tcpFlowIdle,
		udpIdle:   udpFlowIdle,
	}, nil
}

// ApplyPolicy atomically replaces routing policy and removes flows it no longer authorizes.
func (router *Router) ApplyPolicy(configuration config.VirtualNetworkConfig) error {
	policy, err := buildRoutingPolicy(configuration)
	if err != nil {
		return err
	}
	router.mutex.Lock()
	previous := router.policy
	router.policy = policy
	for key, state := range router.flows {
		firstIP, secondIP := netip.AddrFrom4(key.firstIP), netip.AddrFrom4(key.secondIP)
		first, firstExists := policy.byIP[firstIP]
		second, secondExists := policy.byIP[secondIP]
		if !firstExists || !secondExists ||
			first.clientID != previous.byIP[firstIP].clientID || second.clientID != previous.byIP[secondIP].clientID ||
			!policy.serviceAllowed(state.serviceIP, state.protocol, state.servicePort) {
			router.removeFlowLocked(key)
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
			router.removeFlowLocked(key)
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
		router.policyRejected++
		return Destination{}, ErrSourceRejected
	}
	return router.routeLocked(flow, now)
}

// AuthorizePeerFlow validates and records the first packet metadata of a direct flow.
// The resulting state allows the same flow to fall back through the center router.
func (router *Router) AuthorizePeerFlow(clientID string, flow Flow, now time.Time) (Destination, error) {
	if !flow.SourceIP.Is4() || !flow.DestinationIP.Is4() ||
		(flow.Protocol != protocolTCP && flow.Protocol != protocolUDP) {
		return Destination{}, ErrInvalidPacket
	}
	router.mutex.Lock()
	defer router.mutex.Unlock()
	ownedIP, exists := router.policy.byClientID[clientID]
	if !exists || ownedIP != flow.SourceIP {
		router.policyRejected++
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
		router.policyRejected++
		return Destination{}, ErrSourceRejected
	}
	return router.routeLocked(flow, now)
}

func (router *Router) routeLocked(flow Flow, now time.Time) (Destination, error) {
	target, exists := router.policy.byIP[flow.DestinationIP]
	if !exists {
		router.policyRejected++
		return Destination{}, ErrTargetUnavailable
	}
	if router.nextCleanup.IsZero() || !now.Before(router.nextCleanup) {
		router.removeExpiredLocked(now, routerCleanupBatchSize)
		router.nextCleanup = now.Add(time.Second)
	}
	key := makeFlowKey(flow)
	state, active := router.flows[key]
	if active && (!now.Before(state.expiresAt) ||
		!router.policy.serviceAllowed(state.serviceIP, state.protocol, state.servicePort)) {
		router.removeFlowLocked(key)
		active = false
	}
	if !active {
		if flow.Protocol == protocolTCP && !flow.IsTCPStart() {
			router.policyRejected++
			return Destination{}, ErrFlowRejected
		}
		if !target.allows(flow.Protocol, flow.DestinationPort) {
			router.policyRejected++
			return Destination{}, ErrFlowRejected
		}
		atCapacity := func() bool {
			return len(router.flows) >= router.maxFlows ||
				router.nodeFlows[flow.SourceIP] >= routerMaximumNodeFlows ||
				router.nodeFlows[flow.DestinationIP] >= routerMaximumNodeFlows ||
				router.admission.pairs[makeNodePair(flow.SourceIP, flow.DestinationIP)].count >= maximumPairFlows
		}
		if atCapacity() {
			if !now.Before(router.nextCapacityCleanup) {
				router.removeExpiredLocked(now, router.maxFlows)
				router.nextCapacityCleanup = now.Add(time.Second)
			}
			if atCapacity() {
				router.capacityRejected++
				return Destination{}, ErrFlowCapacity
			}
		}
		if err := router.admission.admit(flow, now, router.maxFlows); err != nil {
			if errors.Is(err, ErrFlowRate) {
				router.rateRejected++
			} else {
				router.capacityRejected++
			}
			return Destination{}, err
		}
		state = flowState{
			serviceIP:   flow.DestinationIP,
			servicePort: flow.DestinationPort,
			protocol:    flow.Protocol,
		}
		router.nodeFlows[flow.SourceIP]++
		if flow.DestinationIP != flow.SourceIP {
			router.nodeFlows[flow.DestinationIP]++
		}
		router.flows[key] = state
	}
	if flow.Protocol == protocolTCP {
		state.expiresAt = now.Add(router.tcpIdle)
	} else {
		state.expiresAt = now.Add(router.udpIdle)
	}
	if flow.IsTCPReset() {
		router.removeFlowLocked(key)
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

func (router *Router) removeExpiredLocked(now time.Time, limit int) {
	inspected := 0
	for key, state := range router.flows {
		if !now.Before(state.expiresAt) {
			router.removeFlowLocked(key)
		}
		inspected++
		if inspected >= limit {
			return
		}
	}
}

func (router *Router) removeFlowLocked(key flowKey) {
	if _, exists := router.flows[key]; !exists {
		return
	}
	delete(router.flows, key)
	first, second := netip.AddrFrom4(key.firstIP), netip.AddrFrom4(key.secondIP)
	router.admission.release(first, second)
	for index, address := range []netip.Addr{first, second} {
		if index == 1 && address == first {
			continue
		}
		if router.nodeFlows[address] <= 1 {
			delete(router.nodeFlows, address)
		} else {
			router.nodeFlows[address]--
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
	index := sort.Search(len(ranges), func(index int) bool {
		return ranges[index].End >= port
	})
	return index < len(ranges) && port >= ranges[index].Start
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
