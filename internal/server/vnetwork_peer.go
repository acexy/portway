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
	vnetMaximumNodePeers  = 64
)

type serverVNetPeerPair struct {
	generation uint64
	firstID    string
	secondID   string
	ready      map[string]bool
	expiresAt  time.Time
	retryAfter time.Time
	active     bool
}

func (runtime *serverVNetRuntime) configurePeerCoordinator(address string) {
	runtime.mutex.Lock()
	runtime.peerListenAddress = address
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
		runtime.mutex.Unlock()
		candidates := normalizePeerCandidates(signal.HostCandidates)
		candidates = append(candidates, protocol.VNetPeerCandidate{
			Address: address.String(), Type: protocol.VNetPeerCandidateServerReflexive,
		})
		runtime.mutex.Lock()
		session, exists = runtime.sessions[signal.ClientID]
		if !exists || session.sessionID != signal.SessionID ||
			vnet.VerifyPeerSignal(data, session.peerRegistrationSecret) != nil {
			runtime.mutex.Unlock()
			continue
		}
		session.peerFingerprint = signal.Fingerprint
		session.peerCandidates = candidates
		session.peerAddress = address.String()
		runtime.sessions[signal.ClientID] = session
		runtime.mutex.Unlock()
	}
}

func normalizePeerCandidates(values []string) []protocol.VNetPeerCandidate {
	if len(values) > 15 {
		values = values[:15]
	}
	result := make([]protocol.VNetPeerCandidate, 0, len(values))
	seen := make(map[string]struct{})
	for _, value := range values {
		address, err := netip.ParseAddrPort(value)
		if err != nil || !address.Addr().Is4() || address.Port() == 0 || address.Addr().IsUnspecified() || address.Addr().IsLoopback() || address.Addr().IsMulticast() {
			continue
		}
		normalized := address.String()
		if _, duplicate := seen[normalized]; duplicate {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, protocol.VNetPeerCandidate{Address: normalized, Type: protocol.VNetPeerCandidateHost})
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
	if runtime.peerPairs[key] == nil {
		sourceCount, targetCount := 0, 0
		for _, existing := range runtime.peerPairs {
			if existing.firstID == sourceID || existing.secondID == sourceID {
				sourceCount++
			}
			if existing.firstID == targetID || existing.secondID == targetID {
				targetCount++
			}
		}
		if sourceCount >= vnetMaximumNodePeers || targetCount >= vnetMaximumNodePeers {
			runtime.mutex.Unlock()
			return
		}
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
		ready: make(map[string]bool), expiresAt: time.Now().Add(vnetPeerOfferLifetime),
	}
	runtime.peerPairs[key] = pair

	expires := pair.expiresAt.UnixMilli()
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
	sourceQueued := source.peerNotifier.enqueue(protocol.MessageVNetPeerOffer, sourceOffer)
	targetQueued := target.peerNotifier.enqueue(protocol.MessageVNetPeerOffer, targetOffer)
	runtime.mutex.Unlock()
	if !sourceQueued || !targetQueued {
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
		return nil
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
	if !pair.retryAfter.IsZero() {
		runtime.mutex.Unlock()
		return nil
	}
	if !pair.expiresAt.IsZero() && !time.Now().Before(pair.expiresAt) && !pair.active {
		runtime.failPeerPairLocked(pair, "offer_expired", time.Now())
		runtime.mutex.Unlock()
		return nil
	}
	pair.ready[clientID] = true
	ready := pair.ready[pair.firstID] && pair.ready[pair.secondID]
	activate := ready && !pair.active
	if activate {
		pair.active = true
	}
	first := runtime.sessions[pair.firstID]
	second := runtime.sessions[pair.secondID]
	if activate {
		firstQueued := first.peerNotifier.enqueue(protocol.MessageVNetPeerActivate, protocol.VNetPeerActivate{
			PeerGeneration: pair.generation, PeerClientID: pair.secondID,
		})
		secondQueued := second.peerNotifier.enqueue(protocol.MessageVNetPeerActivate, protocol.VNetPeerActivate{
			PeerGeneration: pair.generation, PeerClientID: pair.firstID,
		})
		runtime.mutex.Unlock()
		if !firstQueued || !secondQueued {
			runtime.failPeerPair(pair.firstID, pair.secondID, pair.generation, "activation_failed")
		}
		return nil
	}
	runtime.mutex.Unlock()
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
	if !exists || session.sessionID != sessionID || pair == nil || !pair.active ||
		pair.generation != request.PeerGeneration {
		runtime.mutex.RUnlock()
		return nil
	}
	defer runtime.mutex.RUnlock()
	sourceIP, sourceError := netip.ParseAddr(request.SourceIP)
	destinationIP, destinationError := netip.ParseAddr(request.DestinationIP)
	if sourceError != nil || destinationError != nil {
		return vnet.ErrInvalidPacket
	}
	configuration := runtime.configuration
	target, configured := config.VNetNode(configuration, request.PeerClientID)
	if !configured || target.IP != request.DestinationIP {
		return vnet.ErrTargetUnavailable
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
	defer runtime.mutex.Unlock()
	pair := runtime.peerPairs[key]
	if pair == nil || pair.generation != generation || !pair.retryAfter.IsZero() {
		return
	}
	runtime.failPeerPairLocked(pair, reason, time.Now())
}

func (runtime *serverVNetRuntime) failPeerPairLocked(pair *serverVNetPeerPair, reason string, now time.Time) {
	pair.ready = make(map[string]bool)
	pair.active = false
	pair.retryAfter = now.Add(vnetPeerRetryDelay)
	runtime.notifyPeerRevocationLocked(pair, reason)
}

func (runtime *serverVNetRuntime) notifyPeerRevocationLocked(pair *serverVNetPeerPair, reason string) {
	for _, ids := range [][2]string{{pair.firstID, pair.secondID}, {pair.secondID, pair.firstID}} {
		if session, exists := runtime.sessions[ids[0]]; exists {
			session.peerNotifier.enqueue(protocol.MessageVNetPeerRevoke, protocol.VNetPeerRevoke{
				PeerGeneration: pair.generation, PeerClientID: ids[1], Reason: reason,
			})
		}
	}
}

func (runtime *serverVNetRuntime) revokeClientPeers(clientID string, reason string) {
	runtime.revokePeers(clientID, reason)
}

func (runtime *serverVNetRuntime) revokeAllPeers(reason string) {
	runtime.revokePeers("", reason)
}

func (runtime *serverVNetRuntime) revokePeers(clientID, reason string) {
	runtime.mutex.Lock()
	defer runtime.mutex.Unlock()
	pairs := make([]*serverVNetPeerPair, 0)
	for key, pair := range runtime.peerPairs {
		if clientID == "" || pair.firstID == clientID || pair.secondID == clientID {
			pair.active = false
			delete(runtime.peerPairs, key)
			pairs = append(pairs, pair)
		}
	}
	// The complete authority barrier precedes every outbound notice.
	for _, pair := range pairs {
		runtime.notifyPeerRevocationLocked(pair, reason)
	}
}

func (runtime *serverVNetRuntime) expirePeerPairs(now time.Time) {
	runtime.mutex.Lock()
	defer runtime.mutex.Unlock()
	for key, pair := range runtime.peerPairs {
		if !pair.retryAfter.IsZero() {
			if !now.Before(pair.retryAfter) {
				delete(runtime.peerPairs, key)
			}
		} else if !pair.active && !pair.expiresAt.IsZero() && !now.Before(pair.expiresAt) {
			runtime.failPeerPairLocked(pair, "offer_expired", now)
		}
	}
}

func (runtime *serverVNetRuntime) maintainPeers() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	nextReport := time.Now().Add(30 * time.Second)
	for {
		select {
		case <-runtime.context.Done():
			return
		case now := <-ticker.C:
			runtime.expirePeerPairs(now)
			if !now.Before(nextReport) {
				runtime.reportVNetStatistics()
				nextReport = now.Add(30 * time.Second)
			}
		}
	}
}

func peerPairKey(left string, right string) (string, string, string) {
	values := []string{left, right}
	sort.Strings(values)
	return values[0] + "\x00" + values[1], values[0], values[1]
}
