package vnet

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/acexy/portway/internal/protocol"
)

// MarkRelay pins a flow to the center path before a direct path is ready.
func (endpoint *PeerEndpoint) MarkRelay(flow Flow, now time.Time) {
	key, ok := peerFlowKey(flow)
	if !ok {
		return
	}
	endpoint.mutex.Lock()
	endpoint.expireFlowsLocked(now)
	if route, exists := endpoint.flowLocked(key, now); exists {
		route.expiresAt = peerFlowExpiry(flow, now)
		endpoint.flows[key] = route
	} else if len(endpoint.flows) < peerMaximumTrackedFlows {
		endpoint.flows[key] = peerFlowRoute{expiresAt: peerFlowExpiry(flow, now)}
	}
	endpoint.mutex.Unlock()
}

// Send sends a packet directly when its flow is assigned to an active peer path.
func (endpoint *PeerEndpoint) Send(flow Flow, packet []byte, now time.Time) (bool, error) {
	key, ok := peerFlowKey(flow)
	if !ok || len(packet) == 0 || len(packet) > int(endpoint.mtu) {
		return false, nil
	}
	endpoint.mutex.Lock()
	endpoint.expireFlowsLocked(now)
	route, exists := endpoint.flowLocked(key, now)
	state := endpoint.activeByIP[flow.DestinationIP]
	if exists && !route.direct {
		route.expiresAt = peerFlowExpiry(flow, now)
		endpoint.flows[key] = route
		endpoint.mutex.Unlock()
		return false, nil
	}
	if state == nil || !state.active || state.connection == nil {
		endpoint.mutex.Unlock()
		return false, nil
	}
	if !exists {
		if len(endpoint.flows) >= peerMaximumTrackedFlows {
			endpoint.capacityRejected++
			endpoint.mutex.Unlock()
			return true, nil
		}
		if flow.Protocol == protocolTCP && !flow.IsTCPStart() {
			endpoint.mutex.Unlock()
			return false, nil
		}
		if !endpoint.admitFlowLocked(flow, now) {
			endpoint.mutex.Unlock()
			return true, nil
		}
		route = peerFlowRoute{direct: true, generation: state.offer.PeerGeneration, opener: flow, expiresAt: peerFlowExpiry(flow, now)}
		endpoint.flows[key] = route
	}
	if !route.direct || route.generation != state.offer.PeerGeneration {
		endpoint.mutex.Unlock()
		return false, nil
	}
	if err := endpoint.renewFlowLocked(state, &route, now); err != nil {
		endpoint.mutex.Unlock()
		endpoint.failPath(state, "flow_registration_failed")
		return false, err
	}
	if current, present := endpoint.flowLocked(key, now); present {
		if !current.direct || current.generation != route.generation {
			endpoint.mutex.Unlock()
			return false, nil
		}
	} else {
		endpoint.mutex.Unlock()
		return true, nil
	}
	route.expiresAt = peerFlowExpiry(flow, now)
	endpoint.flows[key] = route
	connection := state.connection
	generation := state.offer.PeerGeneration
	if flow.IsTCPReset() {
		endpoint.removeFlowLocked(key)
	}
	endpoint.mutex.Unlock()
	frame := make([]byte, peerDatagramHeaderSize+len(packet))
	frame[0] = peerDatagramVersion
	binary.BigEndian.PutUint64(frame[2:10], generation)
	binary.BigEndian.PutUint16(frame[10:12], uint16(len(packet)))
	copy(frame[12:], packet)
	if err := connection.SendDatagram(frame); err != nil {
		endpoint.failPath(state, "datagram_send_failed")
		return true, err
	}
	return true, nil
}

func (endpoint *PeerEndpoint) authorizeInbound(state *peerOfferState, flow Flow, now time.Time) bool {
	key, ok := peerFlowKey(flow)
	if !ok {
		return false
	}
	endpoint.mutex.Lock()
	defer endpoint.mutex.Unlock()
	if endpoint.offers[state.offer.PeerGeneration] != state || !state.active {
		return false
	}
	endpoint.expireFlowsLocked(now)
	route, exists := endpoint.flowLocked(key, now)
	if !exists {
		if len(endpoint.flows) >= peerMaximumTrackedFlows {
			endpoint.capacityRejected++
			return false
		}
		if (flow.Protocol == protocolTCP && !flow.IsTCPStart()) ||
			!peerPortAllowed(state.offer, flow.Protocol, flow.DestinationPort) {
			return false
		}
		if !endpoint.admitFlowLocked(flow, now) {
			return false
		}
		route = peerFlowRoute{direct: true, generation: state.offer.PeerGeneration, expiresAt: peerFlowExpiry(flow, now)}
		endpoint.flows[key] = route
	}
	if !route.direct || route.generation != state.offer.PeerGeneration {
		return false
	}
	if endpoint.renewFlowLocked(state, &route, now) != nil {
		return false
	}
	if current, present := endpoint.flows[key]; !present || !current.direct || current.generation != route.generation {
		return false
	}
	route.expiresAt = peerFlowExpiry(flow, now)
	endpoint.flows[key] = route
	if flow.IsTCPReset() {
		endpoint.removeFlowLocked(key)
	}
	return true
}

func peerPortAllowed(offer protocol.VNetPeerOffer, networkProtocol uint8, port uint16) bool {
	ranges := offer.InboundUDP
	if networkProtocol == protocolTCP {
		ranges = offer.InboundTCP
	}
	for _, portRange := range ranges {
		if port >= portRange.Start && port <= portRange.End {
			return true
		}
	}
	return false
}

func peerFlowKey(flow Flow) ([13]byte, bool) {
	if !flow.SourceIP.Is4() || !flow.DestinationIP.Is4() ||
		(flow.Protocol != protocolTCP && flow.Protocol != protocolUDP) {
		return [13]byte{}, false
	}
	firstIP, firstPort := flow.SourceIP, flow.SourcePort
	secondIP, secondPort := flow.DestinationIP, flow.DestinationPort
	if endpointLess(secondIP, secondPort, firstIP, firstPort) {
		firstIP, secondIP = secondIP, firstIP
		firstPort, secondPort = secondPort, firstPort
	}
	key := [13]byte{flow.Protocol}
	first, second := firstIP.As4(), secondIP.As4()
	copy(key[1:5], first[:])
	binary.BigEndian.PutUint16(key[5:7], firstPort)
	copy(key[7:11], second[:])
	binary.BigEndian.PutUint16(key[11:13], secondPort)
	return key, true
}

func peerFlowExpiry(flow Flow, now time.Time) time.Time {
	if flow.Protocol == protocolUDP {
		return now.Add(peerUDPFlowIdle)
	}
	return now.Add(peerTCPFlowIdle)
}

func (endpoint *PeerEndpoint) flowLocked(key [13]byte, now time.Time) (peerFlowRoute, bool) {
	route, exists := endpoint.flows[key]
	if exists && !now.Before(route.expiresAt) {
		endpoint.removeFlowLocked(key)
		return peerFlowRoute{}, false
	}
	return route, exists
}

func (endpoint *PeerEndpoint) renewFlowLocked(state *peerOfferState, route *peerFlowRoute, now time.Time) error {
	if route.opener.SourceIP != endpoint.virtualIP || now.Before(route.renewAt) || endpoint.openFlow == nil {
		return nil
	}
	// Control I/O must not hold the endpoint lock: a concurrently received
	// revocation must be able to disable this path before the write completes.
	opener := endpoint.openFlow
	endpoint.mutex.Unlock()
	err := opener(state.offer.PeerGeneration, state.offer.PeerClientID, route.opener)
	endpoint.mutex.Lock()
	if err != nil {
		return err
	}
	if endpoint.offers[state.offer.PeerGeneration] != state || !state.active {
		return net.ErrClosed
	}
	route.renewAt = now.Add(peerFlowRenewInterval)
	return nil
}

func (endpoint *PeerEndpoint) expireFlowsLocked(now time.Time) {
	if now.Before(endpoint.nextCleanup) {
		return
	}
	endpoint.nextCleanup = now.Add(time.Second)
	for key, route := range endpoint.flows {
		if !now.Before(route.expiresAt) {
			endpoint.removeFlowLocked(key)
		}
	}
}

func (endpoint *PeerEndpoint) admitFlowLocked(flow Flow, now time.Time) bool {
	err := endpoint.admission.admit(flow, now, peerMaximumTrackedFlows)
	if errors.Is(err, ErrFlowRate) {
		endpoint.rateRejected++
	} else if err != nil {
		endpoint.capacityRejected++
	}
	return err == nil
}

func (endpoint *PeerEndpoint) removeFlowLocked(key [13]byte) {
	if route, exists := endpoint.flows[key]; exists && route.direct {
		endpoint.admission.release(netip.AddrFrom4([4]byte(key[1:5])), netip.AddrFrom4([4]byte(key[7:11])))
	}
	delete(endpoint.flows, key)
}
