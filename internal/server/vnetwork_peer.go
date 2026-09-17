package server

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/vnet"
)

const (
	vnetPeerOfferLifetime = 15 * time.Second
	vnetPeerRetryDelay    = 10 * time.Second
	vnetMaximumPeerPairs  = 4096
)

type serverVNetPeerPair struct {
	generation uint64
	firstID    string
	secondID   string
	ready      map[string]bool
	retryAfter time.Time
	active     bool
}

func (runtime *serverVNetRuntime) configurePeerCoordinator(address string, fatal func(error)) {
	runtime.mutex.Lock()
	runtime.peerListenAddress = address
	runtime.peerFatal = fatal
	runtime.mutex.Unlock()
}

func (runtime *serverVNetRuntime) startPeerCoordinator(address string) error {
	peerAddress, err := vnet.PeerUDPAddress(address, false)
	if err != nil {
		return err
	}
	udpAddress, err := net.ResolveUDPAddr("udp4", peerAddress)
	if err != nil {
		return err
	}
	connection, err := net.ListenUDP("udp4", udpAddress)
	if err != nil {
		return err
	}
	runtime.mutex.Lock()
	if runtime.peerConnection != nil {
		runtime.mutex.Unlock()
		connection.Close()
		return errors.New("VNet peer coordinator is already running")
	}
	runtime.peerConnection = connection
	runtime.mutex.Unlock()
	runtime.waitGroup.Go(func() { runtime.readPeerRegistrations(connection) })
	runtime.logger.InfoWithFields("VNet P2P coordinator started", map[string]any{
		"event": "vnet_p2p_coordinator_started", "listen_address": peerAddress,
	})
	return nil
}

func (runtime *serverVNetRuntime) stopPeerCoordinator() {
	runtime.mutex.Lock()
	connection := runtime.peerConnection
	runtime.peerConnection = nil
	runtime.mutex.Unlock()
	if connection != nil {
		_ = connection.Close()
	}
}

func (runtime *serverVNetRuntime) readPeerRegistrations(connection *net.UDPConn) {
	buffer := make([]byte, 4096)
	for {
		length, address, err := connection.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		data := append([]byte(nil), buffer[:length]...)
		signal, err := vnet.ParsePeerSignal(data)
		if err != nil || signal.Kind != vnet.PeerSignalRegister || signal.SessionID == "" || signal.Fingerprint == "" {
			continue
		}
		runtime.mutex.Lock()
		session, exists := runtime.sessions[signal.ClientID]
		if !exists || session.sessionID != signal.SessionID ||
			vnet.VerifyPeerSignal(data, session.peerRegistrationSecret) != nil {
			runtime.mutex.Unlock()
			continue
		}
		candidates := normalizePeerCandidates(signal.HostCandidates)
		candidates = append(candidates, protocol.VNetPeerCandidate{
			Address: address.String(), Type: "server_reflexive",
		})
		session.peerFingerprint = signal.Fingerprint
		session.peerCandidates = candidates
		session.peerAddress = address.String()
		runtime.sessions[signal.ClientID] = session
		runtime.mutex.Unlock()
	}
}

func normalizePeerCandidates(values []string) []protocol.VNetPeerCandidate {
	if len(values) > 16 {
		values = values[:16]
	}
	result := make([]protocol.VNetPeerCandidate, 0, len(values))
	seen := make(map[string]struct{})
	for _, value := range values {
		address, err := net.ResolveUDPAddr("udp4", value)
		if err != nil || address.IP == nil || address.IP.IsUnspecified() || address.IP.IsLoopback() || address.IP.IsMulticast() {
			continue
		}
		normalized := address.String()
		if _, duplicate := seen[normalized]; duplicate {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, protocol.VNetPeerCandidate{Address: normalized, Type: "host"})
	}
	return result
}

func (runtime *serverVNetRuntime) offerPeer(sourceID string, targetID string) {
	key, firstID, secondID := peerPairKey(sourceID, targetID)
	runtime.mutex.Lock()
	if existing := runtime.peerPairs[key]; existing != nil &&
		(existing.retryAfter.IsZero() || time.Now().Before(existing.retryAfter)) {
		runtime.mutex.Unlock()
		return
	}
	if runtime.peerPairs[key] == nil && len(runtime.peerPairs) >= vnetMaximumPeerPairs {
		runtime.mutex.Unlock()
		return
	}
	source, sourceExists := runtime.sessions[sourceID]
	target, targetExists := runtime.sessions[targetID]
	configuration := runtime.configuration
	if !sourceExists || !targetExists || source.peerFingerprint == "" || target.peerFingerprint == "" ||
		runtime.brokerActiveMissing(sourceID) || runtime.brokerActiveMissing(targetID) {
		runtime.mutex.Unlock()
		return
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		runtime.mutex.Unlock()
		return
	}
	generation := runtime.peerSequence.Add(1)
	pair := &serverVNetPeerPair{
		generation: generation, firstID: firstID, secondID: secondID,
		ready: make(map[string]bool),
	}
	runtime.peerPairs[key] = pair
	runtime.mutex.Unlock()

	expires := time.Now().Add(vnetPeerOfferLifetime).UnixMilli()
	secretText := base64.RawURLEncoding.EncodeToString(secret)
	sourceNode, _ := config.VNetNode(configuration, sourceID)
	targetNode, _ := config.VNetNode(configuration, targetID)
	sourceOffer := protocol.VNetPeerOffer{
		PeerGeneration: generation, PeerClientID: targetID, PeerVirtualIP: targetNode.IP,
		PeerFingerprint: target.peerFingerprint, PairTicket: secretText,
		Role: protocol.VNetPeerRoleClient, Candidates: append([]protocol.VNetPeerCandidate(nil), target.peerCandidates...),
		InboundTCP: peerPortRanges(sourceNode.Ports.TCP.PortRanges),
		InboundUDP: peerPortRanges(sourceNode.Ports.UDP.PortRanges), ExpiresAtUnixMS: expires,
	}
	targetOffer := protocol.VNetPeerOffer{
		PeerGeneration: generation, PeerClientID: sourceID, PeerVirtualIP: sourceNode.IP,
		PeerFingerprint: source.peerFingerprint, PairTicket: secretText,
		Role: protocol.VNetPeerRoleServer, Candidates: append([]protocol.VNetPeerCandidate(nil), source.peerCandidates...),
		InboundTCP: peerPortRanges(targetNode.Ports.TCP.PortRanges),
		InboundUDP: peerPortRanges(targetNode.Ports.UDP.PortRanges), ExpiresAtUnixMS: expires,
	}
	if source.writer.Write(protocol.MessageVNetPeerOffer, sourceOffer) != nil ||
		target.writer.Write(protocol.MessageVNetPeerOffer, targetOffer) != nil {
		runtime.failPeerPair(sourceID, targetID, generation, "offer_failed")
	}
}

func (runtime *serverVNetRuntime) brokerActiveMissing(clientID string) bool {
	_, exists := runtime.broker.Active(clientID)
	return !exists
}

func peerPortRanges(ranges []config.PortRange) []protocol.VNetPeerPortRange {
	result := make([]protocol.VNetPeerPortRange, len(ranges))
	for index, portRange := range ranges {
		result[index] = protocol.VNetPeerPortRange{Start: portRange.Start, End: portRange.End}
	}
	return result
}

func (runtime *serverVNetRuntime) peerStatus(clientID string, sessionID string, status protocol.VNetPeerStatus) error {
	key, _, _ := peerPairKey(clientID, status.PeerClientID)
	runtime.mutex.Lock()
	session, exists := runtime.sessions[clientID]
	pair := runtime.peerPairs[key]
	if !exists || session.sessionID != sessionID || pair == nil || pair.generation != status.PeerGeneration {
		runtime.mutex.Unlock()
		return errors.New("VNet peer status does not match current pair")
	}
	switch status.State {
	case protocol.VNetPeerStateFailed, protocol.VNetPeerStateClosed:
		runtime.mutex.Unlock()
		runtime.failPeerPair(clientID, status.PeerClientID, status.PeerGeneration, status.Code)
		return nil
	case protocol.VNetPeerStateReady:
	default:
		runtime.mutex.Unlock()
		return errors.New("invalid VNet peer status")
	}
	pair.ready[clientID] = true
	ready := pair.ready[pair.firstID] && pair.ready[pair.secondID]
	activate := ready && !pair.active
	if activate {
		pair.active = true
	}
	first := runtime.sessions[pair.firstID]
	second := runtime.sessions[pair.secondID]
	runtime.mutex.Unlock()
	if activate {
		_ = first.writer.Write(protocol.MessageVNetPeerActivate, protocol.VNetPeerActivate{
			PeerGeneration: pair.generation, PeerClientID: pair.secondID,
		})
		_ = second.writer.Write(protocol.MessageVNetPeerActivate, protocol.VNetPeerActivate{
			PeerGeneration: pair.generation, PeerClientID: pair.firstID,
		})
	}
	return nil
}

func (runtime *serverVNetRuntime) openPeerFlow(
	clientID string,
	sessionID string,
	request protocol.VNetPeerFlowOpen,
) error {
	key, _, _ := peerPairKey(clientID, request.PeerClientID)
	runtime.mutex.RLock()
	session, exists := runtime.sessions[clientID]
	pair := runtime.peerPairs[key]
	runtime.mutex.RUnlock()
	if !exists || session.sessionID != sessionID || pair == nil || !pair.active ||
		pair.generation != request.PeerGeneration {
		return errors.New("VNet peer flow does not match an active pair")
	}
	sourceIP, sourceError := netip.ParseAddr(request.SourceIP)
	destinationIP, destinationError := netip.ParseAddr(request.DestinationIP)
	if sourceError != nil || destinationError != nil {
		return vnet.ErrInvalidPacket
	}
	destination, err := runtime.router.AuthorizePeerFlow(clientID, vnet.Flow{
		Protocol: request.Protocol, SourceIP: sourceIP, SourcePort: request.SourcePort,
		DestinationIP: destinationIP, DestinationPort: request.DestinationPort,
		TCPFlags: request.TCPFlags,
	}, time.Now())
	if err != nil {
		return err
	}
	if destination.Kind != vnet.DestinationClient || destination.ClientID != request.PeerClientID {
		return vnet.ErrTargetUnavailable
	}
	return nil
}

func (runtime *serverVNetRuntime) failPeerPair(firstID, secondID string, generation uint64, reason string) {
	key, _, _ := peerPairKey(firstID, secondID)
	runtime.mutex.Lock()
	pair := runtime.peerPairs[key]
	if pair == nil || pair.generation != generation {
		runtime.mutex.Unlock()
		return
	}
	pair.ready = make(map[string]bool)
	pair.active = false
	pair.retryAfter = time.Now().Add(vnetPeerRetryDelay)
	first, firstExists := runtime.sessions[firstID]
	second, secondExists := runtime.sessions[secondID]
	runtime.mutex.Unlock()
	if firstExists {
		_ = first.writer.Write(protocol.MessageVNetPeerRevoke, protocol.VNetPeerRevoke{
			PeerGeneration: generation, PeerClientID: secondID, Reason: reason,
		})
	}
	if secondExists {
		_ = second.writer.Write(protocol.MessageVNetPeerRevoke, protocol.VNetPeerRevoke{
			PeerGeneration: generation, PeerClientID: firstID, Reason: reason,
		})
	}
}

func (runtime *serverVNetRuntime) revokeClientPeers(clientID string, reason string) {
	runtime.mutex.RLock()
	pairs := make([]*serverVNetPeerPair, 0)
	for _, pair := range runtime.peerPairs {
		if pair.firstID == clientID || pair.secondID == clientID {
			pairs = append(pairs, pair)
		}
	}
	runtime.mutex.RUnlock()
	for _, pair := range pairs {
		runtime.failPeerPair(pair.firstID, pair.secondID, pair.generation, reason)
		runtime.removePeerPair(pair)
	}
}

func (runtime *serverVNetRuntime) revokeAllPeers(reason string) {
	runtime.mutex.RLock()
	pairs := make([]*serverVNetPeerPair, 0, len(runtime.peerPairs))
	for _, pair := range runtime.peerPairs {
		pairs = append(pairs, pair)
	}
	runtime.mutex.RUnlock()
	for _, pair := range pairs {
		runtime.failPeerPair(pair.firstID, pair.secondID, pair.generation, reason)
		runtime.removePeerPair(pair)
	}
}

func (runtime *serverVNetRuntime) removePeerPair(pair *serverVNetPeerPair) {
	key, _, _ := peerPairKey(pair.firstID, pair.secondID)
	runtime.mutex.Lock()
	if runtime.peerPairs[key] == pair {
		delete(runtime.peerPairs, key)
	}
	runtime.mutex.Unlock()
}

func peerPairKey(left string, right string) (string, string, string) {
	values := []string{left, right}
	sort.Strings(values)
	return values[0] + "\x00" + values[1], values[0], values[1]
}
