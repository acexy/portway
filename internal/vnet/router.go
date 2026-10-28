package vnet

import (
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/vnet/internal/flowcontrol"
	packetdata "github.com/acexy/portway/internal/vnet/packet"
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
	ErrFlowCapacity = flowcontrol.ErrFlowCapacity
	// ErrFlowRate indicates that a node pair exhausted its new-flow budget.
	ErrFlowRate = flowcontrol.ErrFlowRate
)

// DestinationKind identifies the owner of one routed packet.
type DestinationKind uint8

const (
	DestinationServer DestinationKind = iota + 1
	DestinationClient
)

// Destination identifies the VNet endpoint and channel selected for one packet.
type Destination struct {
	PolicyGeneration uint64
	Kind             DestinationKind
	ClientID         string
	VirtualIP        netip.Addr
	ChannelIndex     uint8
}

type endpointPolicy struct {
	clientID string
	tcp      []config.PortRange
	udp      []config.PortRange
}

type routingPolicy struct {
	enabled        bool
	serverIP       netip.Addr
	packetChannels uint8
	byIP           map[netip.Addr]endpointPolicy
	byClientID     map[string]netip.Addr
}

type flowState struct {
	serviceIP   netip.Addr
	servicePort uint16
	protocol    uint8
	expiresAt   time.Time
}

// Router owns the bounded authorization state for VNet packet routing.
type Router struct {
	policyGeneration    uint64
	mutex               sync.Mutex
	admission           flowcontrol.Admission
	capacityRejected    uint64
	rateRejected        uint64
	policyRejected      uint64
	policy              routingPolicy
	flows               map[packetdata.Key]flowState
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
		flows:     make(map[packetdata.Key]flowState),
		nodeFlows: make(map[netip.Addr]int),
		maxFlows:  maxFlows,
		tcpIdle:   flowcontrol.TCPFlowIdle,
		udpIdle:   flowcontrol.UDPFlowIdle,
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
	router.policyGeneration++
	for key, state := range router.flows {
		firstIP, secondIP := netip.AddrFrom4(key.FirstIP), netip.AddrFrom4(key.SecondIP)
		first, firstExists := policy.byIP[firstIP]
		second, secondExists := policy.byIP[secondIP]
		if !policy.enabled || !firstExists || !secondExists ||
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
	router.policyGeneration++
	address := clientIP.As4()
	for key := range router.flows {
		if key.FirstIP == address || key.SecondIP == address {
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
	flow, err := packetdata.ParseIPv4(packet)
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
func (router *Router) AuthorizePeerFlow(clientID string, flow packetdata.Flow, now time.Time) (Destination, error) {
	if !flow.SourceIP.Is4() || !flow.DestinationIP.Is4() ||
		(flow.Protocol != packetdata.ProtocolTCP && flow.Protocol != packetdata.ProtocolUDP) {
		return Destination{}, packetdata.ErrInvalidPacket
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
	flow, err := packetdata.ParseIPv4(packet)
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

func (router *Router) routeLocked(flow packetdata.Flow, now time.Time) (Destination, error) {
	if !router.policy.enabled {
		router.policyRejected++
		return Destination{}, ErrFlowRejected
	}
	target, exists := router.policy.byIP[flow.DestinationIP]
	if !exists {
		router.policyRejected++
		return Destination{}, ErrTargetUnavailable
	}
	if router.nextCleanup.IsZero() || !now.Before(router.nextCleanup) {
		router.removeExpiredLocked(now, routerCleanupBatchSize)
		router.nextCleanup = now.Add(time.Second)
	}
	key := packetdata.MakeKey(flow)
	state, active := router.flows[key]
	if active && (!now.Before(state.expiresAt) ||
		!router.policy.serviceAllowed(state.serviceIP, state.protocol, state.servicePort)) {
		router.removeFlowLocked(key)
		active = false
	}
	if !active {
		if flow.Protocol == packetdata.ProtocolTCP && !flow.IsTCPStart() {
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
				router.admission.Count(flow.SourceIP, flow.DestinationIP) >= flowcontrol.MaximumPairFlows
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
		if err := router.admission.Admit(flow, now, router.maxFlows); err != nil {
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
	if flow.Protocol == packetdata.ProtocolTCP {
		state.expiresAt = now.Add(router.tcpIdle)
	} else {
		state.expiresAt = now.Add(router.udpIdle)
	}
	if flow.IsTCPReset() {
		router.removeFlowLocked(key)
	} else {
		router.flows[key] = state
	}
	channelIndex, err := packetdata.ChannelIndex(flow, router.policy.packetChannels)
	if err != nil {
		return Destination{}, err
	}
	destination := Destination{VirtualIP: flow.DestinationIP, ChannelIndex: channelIndex, PolicyGeneration: router.policyGeneration}
	if flow.DestinationIP == router.policy.serverIP {
		destination.Kind = DestinationServer
	} else {
		destination.Kind = DestinationClient
		destination.ClientID = target.clientID
	}
	return destination, nil
}

// IsCurrent rejects queued packets authorized before a policy publication.
func (router *Router) IsCurrent(destination Destination) bool {
	router.mutex.Lock()
	defer router.mutex.Unlock()
	return router.policy.enabled && router.policyGeneration == destination.PolicyGeneration
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

func (router *Router) removeFlowLocked(key packetdata.Key) {
	if _, exists := router.flows[key]; !exists {
		return
	}
	delete(router.flows, key)
	first, second := netip.AddrFrom4(key.FirstIP), netip.AddrFrom4(key.SecondIP)
	router.admission.Release(first, second)
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
		enabled:        configuration.Enabled,
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
	if protocol == packetdata.ProtocolTCP {
		ranges = policy.tcp
	} else if protocol != packetdata.ProtocolUDP {
		return false
	}
	index := sort.Search(len(ranges), func(index int) bool {
		return ranges[index].End >= port
	})
	return index < len(ranges) && port >= ranges[index].Start
}
