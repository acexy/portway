package vnet

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"

	"github.com/acexy/portway/internal/protocol"
)

const (
	peerALPN                  = "portway-vnet-peer"
	peerDatagramVersion       = 1
	peerDatagramHeaderSize    = 12
	peerHandshakeTimeout      = 5 * time.Second
	peerReflexiveProbeDelay   = 200 * time.Millisecond
	peerProbeRetryInterval    = 200 * time.Millisecond
	peerProbeAttempts         = 3
	peerIdleTimeout           = 90 * time.Second
	peerMaximumCandidates     = 16
	peerMaximumHostCandidates = peerMaximumCandidates - 1
	peerMaximumTrackedFlows   = 65536
	peerFlowRenewInterval     = 20 * time.Second
	peerTCPFlowIdle           = tcpFlowIdle
	peerUDPFlowIdle           = udpFlowIdle
	peerApplicationErrorClose = quicgo.ApplicationErrorCode(0x50)
)

// PeerUDPAddress derives the dedicated P+1 UDP address.
func PeerUDPAddress(address string, wildcard bool) (string, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("parse VNet peer base address %q: %w", address, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || port >= 65535 {
		return "", errors.New("VNet peer base port must be between 1 and 65534")
	}
	if wildcard {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)+1)), nil
}

type peerOfferState struct {
	offer               protocol.VNetPeerOffer
	secret              []byte
	connection          *quicgo.Conn
	active              bool
	dialing             bool
	failedCandidates    map[string]bool
	probeAttempts       map[string]int
	validatedCandidates []net.Addr
}

type peerFlowRoute struct {
	direct     bool
	generation uint64
	expiresAt  time.Time
	opener     Flow
	renewAt    time.Time
}

// PeerEndpoint owns session-scoped authority and direct paths on a borrowed socket.
type PeerEndpoint struct {
	context     context.Context
	cancel      context.CancelFunc
	clientID    string
	sessionID   string
	virtualIP   netip.Addr
	mtu         uint16
	connection  *net.UDPConn
	socket      *PeerSocket
	ownsSocket  bool
	transport   *quicgo.Transport
	listener    *quicgo.Listener
	certificate tls.Certificate
	fingerprint string
	status      func(protocol.VNetPeerStatus) error
	receive     func([]byte) error
	openFlow    func(uint64, string, Flow) error

	mutex            sync.Mutex
	admission        flowAdmission
	capacityRejected uint64
	rateRejected     uint64
	fallbacks        uint64
	offers           map[uint64]*peerOfferState
	activeByIP       map[netip.Addr]*peerOfferState
	flows            map[[13]byte]peerFlowRoute
	waitGroup        sync.WaitGroup
	closeOnce        sync.Once
	nextCleanup      time.Time
}

// SetFlowOpener registers the control-plane fallback authorization callback.
func (endpoint *PeerEndpoint) SetFlowOpener(opener func(uint64, string, Flow) error) {
	endpoint.mutex.Lock()
	endpoint.openFlow = opener
	endpoint.mutex.Unlock()
}

// NewPeerEndpoint binds the dedicated P+1 UDP socket.
func NewPeerEndpoint(
	parent context.Context,
	bindAddress string,
	clientID string,
	sessionID string,
	virtualIP string,
	mtu uint16,
	status func(protocol.VNetPeerStatus) error,
	receive func([]byte) error,
) (*PeerEndpoint, error) {
	socket, err := NewPeerSocket(bindAddress)
	if err != nil {
		return nil, err
	}
	endpoint, err := socket.NewEndpoint(parent, clientID, sessionID, virtualIP, mtu, status, receive)
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	endpoint.ownsSocket = true
	return endpoint, nil
}

func newPeerEndpoint(parent context.Context, socket *PeerSocket, clientID, sessionID, virtualIP string, mtu uint16,
	status func(protocol.VNetPeerStatus) error, receive func([]byte) error) (*PeerEndpoint, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	certificate, fingerprint, err := newPeerCertificate(clientID)
	if err != nil {
		return nil, err
	}
	parsedIP, err := netip.ParseAddr(virtualIP)
	if err != nil || !parsedIP.Is4() {
		return nil, errors.New("invalid VNet P2P virtual address")
	}
	ctx, cancel := context.WithCancel(parent)
	endpoint := &PeerEndpoint{
		context: ctx, cancel: cancel, clientID: clientID, sessionID: sessionID,
		virtualIP: parsedIP, mtu: mtu, connection: socket.connection, socket: socket, transport: socket.transport,
		certificate: certificate, fingerprint: fingerprint, status: status, receive: receive,
		offers: make(map[uint64]*peerOfferState), activeByIP: make(map[netip.Addr]*peerOfferState),
		flows: make(map[[13]byte]peerFlowRoute),
	}
	listener, err := endpoint.transport.Listen(endpoint.baseServerTLS(), endpoint.quicConfig())
	if err != nil {
		socket.broken.Store(true)
		cancel()
		return nil, fmt.Errorf("listen for VNet peer QUIC: %w", err)
	}
	endpoint.listener = listener
	return endpoint, nil
}

// Fingerprint returns the ephemeral certificate fingerprint.
func (endpoint *PeerEndpoint) Fingerprint() string { return endpoint.fingerprint }

// HostCandidates returns bounded IPv4 host candidates using the bound port.
func (endpoint *PeerEndpoint) HostCandidates() []string {
	port := endpoint.connection.LocalAddr().(*net.UDPAddr).Port
	interfaces, _ := net.Interfaces()
	candidates := make([]string, 0, min(len(interfaces), peerMaximumHostCandidates))
	seen := make(map[string]struct{})
	for _, interfaceValue := range interfaces {
		if interfaceValue.Flags&net.FlagUp == 0 || interfaceValue.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := interfaceValue.Addrs()
		for _, address := range addresses {
			prefix, parseError := netip.ParsePrefix(address.String())
			if parseError != nil || !prefix.Addr().Is4() || prefix.Addr().IsLoopback() ||
				prefix.Addr().IsMulticast() || prefix.Addr().IsUnspecified() {
				continue
			}
			candidate := net.JoinHostPort(prefix.Addr().String(), strconv.Itoa(port))
			if _, duplicate := seen[candidate]; duplicate {
				continue
			}
			seen[candidate] = struct{}{}
			candidates = append(candidates, candidate)
			if len(candidates) == peerMaximumHostCandidates {
				return candidates
			}
		}
	}
	return candidates
}

// Register sends an authenticated mapping registration to the coordinator.
func (endpoint *PeerEndpoint) Register(serverAddress string, ticket string) error {
	endpoint.mutex.Lock()
	if err := endpoint.context.Err(); err != nil {
		endpoint.mutex.Unlock()
		return err
	}
	endpoint.waitGroup.Add(1)
	endpoint.mutex.Unlock()
	defer endpoint.waitGroup.Done()
	secret, err := base64.RawURLEncoding.DecodeString(ticket)
	if err != nil || len(secret) < 16 {
		return errors.New("invalid VNet P2P registration ticket")
	}
	target, err := net.ResolveUDPAddr("udp4", serverAddress)
	if err != nil {
		return fmt.Errorf("resolve VNet P2P coordinator: %w", err)
	}
	message, err := EncodePeerSignal(PeerSignal{
		Kind: PeerSignalRegister, ClientID: endpoint.clientID, SessionID: endpoint.sessionID,
		Fingerprint: endpoint.fingerprint, HostCandidates: endpoint.HostCandidates(),
	}, secret)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 3; attempt++ {
		if _, err = endpoint.transport.WriteTo(message, target); err != nil {
			return err
		}
	}
	return nil
}

// ApplyOffer starts bounded connectivity checks for one pair.
func (endpoint *PeerEndpoint) ApplyOffer(offer protocol.VNetPeerOffer) error {
	if err := endpoint.context.Err(); err != nil {
		return err
	}
	secret, err := base64.RawURLEncoding.DecodeString(offer.PairTicket)
	peerIP, ipError := netip.ParseAddr(offer.PeerVirtualIP)
	if err != nil || len(secret) < 16 || ipError != nil || !peerIP.Is4() ||
		offer.PeerGeneration == 0 || offer.PeerClientID == "" || offer.PeerClientID == endpoint.clientID ||
		(offer.Role != protocol.VNetPeerRoleClient && offer.Role != protocol.VNetPeerRoleServer) ||
		offer.ExpiresAtUnixMS <= time.Now().UnixMilli() || len(offer.Candidates) > peerMaximumCandidates {
		return errors.New("invalid VNet peer offer")
	}
	for _, candidate := range offer.Candidates {
		if candidate.Type != protocol.VNetPeerCandidateHost &&
			candidate.Type != protocol.VNetPeerCandidateServerReflexive {
			return errors.New("invalid VNet peer candidate type")
		}
	}
	state := &peerOfferState{offer: offer, secret: secret, failedCandidates: make(map[string]bool), probeAttempts: make(map[string]int)}
	endpoint.mutex.Lock()
	if err := endpoint.context.Err(); err != nil {
		endpoint.mutex.Unlock()
		return err
	}
	if previous := endpoint.offers[offer.PeerGeneration]; previous != nil {
		endpoint.mutex.Unlock()
		return errors.New("duplicate VNet peer offer")
	}
	// Keep shutdown waiting until every task for this offer has been scheduled.
	endpoint.waitGroup.Add(1)
	defer endpoint.waitGroup.Done()
	endpoint.offers[offer.PeerGeneration] = state
	endpoint.mutex.Unlock()
	hostCandidates := make([]protocol.VNetPeerCandidate, 0, len(offer.Candidates))
	reflexiveCandidates := make([]protocol.VNetPeerCandidate, 0, 1)
	for _, candidate := range offer.Candidates {
		if candidate.Type == protocol.VNetPeerCandidateHost {
			hostCandidates = append(hostCandidates, candidate)
		} else {
			reflexiveCandidates = append(reflexiveCandidates, candidate)
		}
	}
	endpoint.startProbeChecks(state, hostCandidates)
	endpoint.waitGroup.Go(func() {
		timer := time.NewTimer(peerReflexiveProbeDelay)
		defer timer.Stop()
		select {
		case <-endpoint.context.Done():
			return
		case <-timer.C:
		}
		endpoint.mutex.Lock()
		connected := state.connection != nil || state.dialing
		endpoint.mutex.Unlock()
		if !connected {
			endpoint.startProbeChecks(state, reflexiveCandidates)
		}
	})
	endpoint.waitGroup.Go(func() {
		timer := time.NewTimer(time.Until(time.UnixMilli(offer.ExpiresAtUnixMS)))
		defer timer.Stop()
		select {
		case <-endpoint.context.Done():
			return
		case <-timer.C:
		}
		endpoint.mutex.Lock()
		ready := state.connection != nil
		endpoint.mutex.Unlock()
		if !ready {
			endpoint.failPath(state, "probe_timeout")
		}
	})
	return nil
}

func (endpoint *PeerEndpoint) startProbeChecks(
	state *peerOfferState,
	candidates []protocol.VNetPeerCandidate,
) {
	if len(candidates) == 0 {
		return
	}
	endpoint.waitGroup.Go(func() {
		for attempt := 0; attempt < peerProbeAttempts; attempt++ {
			endpoint.mutex.Lock()
			connected := state.connection != nil || endpoint.offers[state.offer.PeerGeneration] != state ||
				time.Now().UnixMilli() >= state.offer.ExpiresAtUnixMS
			endpoint.mutex.Unlock()
			if connected || endpoint.context.Err() != nil {
				return
			}
			endpoint.sendProbes(state, candidates)
			if attempt+1 == peerProbeAttempts {
				return
			}
			timer := time.NewTimer(peerProbeRetryInterval)
			select {
			case <-endpoint.context.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	})
}

func (endpoint *PeerEndpoint) sendProbes(state *peerOfferState, candidates []protocol.VNetPeerCandidate) {
	for _, candidate := range candidates {
		endpoint.mutex.Lock()
		if endpoint.offers[state.offer.PeerGeneration] != state || state.connection != nil ||
			time.Now().UnixMilli() >= state.offer.ExpiresAtUnixMS ||
			state.probeAttempts[candidate.Address] >= peerProbeAttempts {
			endpoint.mutex.Unlock()
			continue
		}
		state.probeAttempts[candidate.Address]++
		endpoint.mutex.Unlock()
		address, resolveError := net.ResolveUDPAddr("udp4", candidate.Address)
		if resolveError != nil {
			continue
		}
		message, encodeError := EncodePeerSignal(PeerSignal{
			Kind: PeerSignalProbe, ClientID: endpoint.clientID, PeerClientID: state.offer.PeerClientID,
			PeerGeneration: state.offer.PeerGeneration,
		}, state.secret)
		if encodeError == nil {
			_, _ = endpoint.transport.WriteTo(message, address)
		}
	}
}

// Activate publishes one ready connection for new flows.
func (endpoint *PeerEndpoint) Activate(activation protocol.VNetPeerActivate) error {
	endpoint.mutex.Lock()
	defer endpoint.mutex.Unlock()
	state := endpoint.offers[activation.PeerGeneration]
	if state == nil || state.connection == nil || state.offer.PeerClientID != activation.PeerClientID {
		return errors.New("VNet peer activation is not ready")
	}
	peerIP, _ := netip.ParseAddr(state.offer.PeerVirtualIP)
	state.active = true
	endpoint.activeByIP[peerIP] = state
	return nil
}

// Revoke closes one generation and removes its path ownership.
func (endpoint *PeerEndpoint) Revoke(revocation protocol.VNetPeerRevoke) {
	endpoint.mutex.Lock()
	state := endpoint.offers[revocation.PeerGeneration]
	var connection *quicgo.Conn
	if state != nil && state.offer.PeerClientID == revocation.PeerClientID {
		connection = state.connection
		state.active = false
		endpoint.relayFlowsLocked(revocation.PeerGeneration)
		delete(endpoint.offers, revocation.PeerGeneration)
		peerIP, _ := netip.ParseAddr(state.offer.PeerVirtualIP)
		if endpoint.activeByIP[peerIP] == state {
			delete(endpoint.activeByIP, peerIP)
		}
	}
	endpoint.mutex.Unlock()
	if connection != nil {
		_ = connection.CloseWithError(peerApplicationErrorClose, "peer path revoked")
	}
}

func (endpoint *PeerEndpoint) readSignals() {
	buffer := make([]byte, peerSignalMaximumSize)
	for {
		length, address, err := endpoint.transport.ReadNonQUICPacket(endpoint.context, buffer)
		if err != nil {
			if endpoint.context.Err() == nil {
				endpoint.socket.broken.Store(true)
			}
			return
		}
		data := append([]byte(nil), buffer[:length]...)
		signal, err := ParsePeerSignal(data)
		if err != nil || signal.Kind == PeerSignalRegister || signal.PeerClientID != endpoint.clientID {
			continue
		}
		endpoint.mutex.Lock()
		state := endpoint.offers[signal.PeerGeneration]
		endpoint.mutex.Unlock()
		if state == nil || state.offer.PeerClientID != signal.ClientID || VerifyPeerSignal(data, state.secret) != nil {
			continue
		}
		if signal.Kind == PeerSignalProbe {
			ack, _ := EncodePeerSignal(PeerSignal{
				Kind: PeerSignalProbeAck, ClientID: endpoint.clientID,
				PeerClientID: signal.ClientID, PeerGeneration: signal.PeerGeneration,
			}, state.secret)
			_, _ = endpoint.transport.WriteTo(ack, address)
			continue
		}
		if signal.Kind == PeerSignalProbeAck && state.offer.Role == protocol.VNetPeerRoleClient {
			endpoint.startDial(state, address)
		}
	}
}

func (endpoint *PeerEndpoint) startDial(state *peerOfferState, address net.Addr) {
	endpoint.mutex.Lock()
	if endpoint.offers[state.offer.PeerGeneration] != state || state.connection != nil ||
		state.failedCandidates[address.String()] || len(state.failedCandidates) >= peerMaximumCandidates ||
		time.Now().UnixMilli() >= state.offer.ExpiresAtUnixMS {
		endpoint.mutex.Unlock()
		return
	}
	found := false
	for _, candidate := range state.validatedCandidates {
		if candidate.String() == address.String() {
			found = true
			break
		}
	}
	if !found {
		if len(state.validatedCandidates) >= peerMaximumCandidates {
			endpoint.mutex.Unlock()
			return
		}
		state.validatedCandidates = append(state.validatedCandidates, address)
	}
	if state.dialing {
		endpoint.mutex.Unlock()
		return
	}
	state.dialing = true
	endpoint.mutex.Unlock()
	endpoint.waitGroup.Go(func() {
		ctx, cancel := context.WithDeadline(endpoint.context, time.UnixMilli(state.offer.ExpiresAtUnixMS))
		defer cancel()
		connection, err := endpoint.transport.Dial(ctx, address, endpoint.clientTLS(state), endpoint.quicConfig())
		if err != nil {
			endpoint.mutex.Lock()
			state.dialing = false
			state.failedCandidates[address.String()] = true
			current := endpoint.offers[state.offer.PeerGeneration] == state
			var next net.Addr
			for _, candidate := range state.validatedCandidates {
				if !state.failedCandidates[candidate.String()] {
					next = candidate
					break
				}
			}
			endpoint.mutex.Unlock()
			if current && endpoint.context.Err() == nil {
				if next != nil {
					endpoint.startDial(state, next)
				}
				endpoint.startProbeChecks(state, state.offer.Candidates)
			}
			return
		}
		endpoint.publishConnection(state, connection)
	})
}

func (endpoint *PeerEndpoint) acceptConnections() {
	for {
		connection, err := endpoint.listener.Accept(endpoint.context)
		if err != nil {
			return
		}
		serverName := connection.ConnectionState().TLS.ServerName
		generation, parseError := parsePeerServerName(serverName)
		endpoint.mutex.Lock()
		state := endpoint.offers[generation]
		endpoint.mutex.Unlock()
		if parseError != nil || state == nil || state.offer.Role != protocol.VNetPeerRoleServer {
			_ = connection.CloseWithError(peerApplicationErrorClose, "invalid peer generation")
			continue
		}
		endpoint.publishConnection(state, connection)
	}
}

func (endpoint *PeerEndpoint) publishConnection(state *peerOfferState, connection *quicgo.Conn) {
	endpoint.mutex.Lock()
	if endpoint.offers[state.offer.PeerGeneration] != state || state.connection != nil ||
		time.Now().UnixMilli() >= state.offer.ExpiresAtUnixMS {
		endpoint.mutex.Unlock()
		_ = connection.CloseWithError(peerApplicationErrorClose, "duplicate peer connection")
		return
	}
	state.connection = connection
	endpoint.mutex.Unlock()
	if endpoint.status != nil {
		_ = endpoint.status(protocol.VNetPeerStatus{
			PeerGeneration: state.offer.PeerGeneration,
			PeerClientID:   state.offer.PeerClientID,
			State:          protocol.VNetPeerStateReady,
		})
	}
	endpoint.waitGroup.Go(func() { endpoint.readDatagrams(state, connection) })
}

func (endpoint *PeerEndpoint) readDatagrams(state *peerOfferState, connection *quicgo.Conn) {
	for {
		frame, err := connection.ReceiveDatagram(endpoint.context)
		if err != nil {
			endpoint.failPath(state, "datagram_receive_failed")
			return
		}
		if len(frame) < peerDatagramHeaderSize || frame[0] != peerDatagramVersion || frame[1] != 0 ||
			binary.BigEndian.Uint64(frame[2:10]) != state.offer.PeerGeneration {
			continue
		}
		length := int(binary.BigEndian.Uint16(frame[10:12]))
		if length == 0 || length > int(endpoint.mtu) || peerDatagramHeaderSize+length != len(frame) {
			continue
		}
		packet := frame[peerDatagramHeaderSize:]
		flow, parseError := ParseIPv4(packet)
		peerIP, _ := netip.ParseAddr(state.offer.PeerVirtualIP)
		if parseError != nil || flow.SourceIP != peerIP || flow.DestinationIP != endpoint.virtualIP ||
			!endpoint.authorizeInbound(state, flow, time.Now()) {
			continue
		}
		if endpoint.receive != nil {
			if err := endpoint.receive(append([]byte(nil), packet...)); err != nil {
				endpoint.failPath(state, "packet_delivery_failed")
				return
			}
		}
	}
}

func (endpoint *PeerEndpoint) failPath(state *peerOfferState, code string) {
	endpoint.mutex.Lock()
	if endpoint.offers[state.offer.PeerGeneration] != state {
		endpoint.mutex.Unlock()
		return
	}
	peerIP, _ := netip.ParseAddr(state.offer.PeerVirtualIP)
	if endpoint.activeByIP[peerIP] == state {
		delete(endpoint.activeByIP, peerIP)
	}
	if state.active {
		endpoint.fallbacks++
	}
	state.active = false
	endpoint.relayFlowsLocked(state.offer.PeerGeneration)
	endpoint.mutex.Unlock()
	if endpoint.status != nil && endpoint.context.Err() == nil {
		_ = endpoint.status(protocol.VNetPeerStatus{
			PeerGeneration: state.offer.PeerGeneration, PeerClientID: state.offer.PeerClientID,
			State: protocol.VNetPeerStateFailed, Code: code,
		})
	}
}

func (endpoint *PeerEndpoint) relayFlowsLocked(generation uint64) {
	for key, route := range endpoint.flows {
		if route.direct && route.generation == generation {
			endpoint.admission.release(netip.AddrFrom4([4]byte(key[1:5])), netip.AddrFrom4([4]byte(key[7:11])))
			route.direct = false
			route.generation = 0
			endpoint.flows[key] = route
		}
	}
}

func (endpoint *PeerEndpoint) baseServerTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{endpoint.certificate},
		NextProtos: []string{peerALPN},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			generation, err := parsePeerServerName(hello.ServerName)
			if err != nil {
				return nil, err
			}
			endpoint.mutex.Lock()
			state := endpoint.offers[generation]
			endpoint.mutex.Unlock()
			if state == nil || state.offer.Role != protocol.VNetPeerRoleServer ||
				time.Now().UnixMilli() >= state.offer.ExpiresAtUnixMS {
				return nil, errors.New("unknown VNet peer generation")
			}
			return &tls.Config{
				MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{endpoint.certificate},
				NextProtos: []string{peerALPN}, ClientAuth: tls.RequireAnyClientCert,
				VerifyPeerCertificate: verifyPeerFingerprint(state.offer.PeerFingerprint),
			}, nil
		},
	}
}

func (endpoint *PeerEndpoint) clientTLS(state *peerOfferState) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{endpoint.certificate},
		NextProtos: []string{peerALPN}, ServerName: peerServerName(state.offer.PeerGeneration),
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyPeerFingerprint(state.offer.PeerFingerprint),
	}
}

func (endpoint *PeerEndpoint) quicConfig() *quicgo.Config {
	return &quicgo.Config{
		HandshakeIdleTimeout: peerHandshakeTimeout, MaxIdleTimeout: peerIdleTimeout,
		KeepAlivePeriod: 20 * time.Second, MaxIncomingStreams: -1, MaxIncomingUniStreams: -1,
		EnableDatagrams: true, Allow0RTT: false,
	}
}

// Close retires this session. Only standalone endpoints own their UDP binding.
func (endpoint *PeerEndpoint) Close() error {
	endpoint.closeSession()
	if endpoint.ownsSocket {
		return endpoint.socket.Close()
	}
	return nil
}

func (endpoint *PeerEndpoint) closeSession() {
	endpoint.closeOnce.Do(func() {
		endpoint.cancel()
		endpoint.mutex.Lock()
		for _, state := range endpoint.offers {
			state.active = false
			if state.connection != nil {
				_ = state.connection.CloseWithError(peerApplicationErrorClose, "peer session closed")
			}
		}
		clear(endpoint.offers)
		clear(endpoint.activeByIP)
		clear(endpoint.flows)
		endpoint.admission = flowAdmission{}
		endpoint.mutex.Unlock()
		if endpoint.listener != nil {
			_ = endpoint.listener.Close()
		}
	})
	endpoint.waitGroup.Wait()
	endpoint.socket.release(endpoint)
}
