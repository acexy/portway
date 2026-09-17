package vnet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
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
	peerMaximumTrackedFlows   = 65536
	peerTCPFlowIdle           = 5 * time.Minute
	peerUDPFlowIdle           = time.Minute
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
	offer      protocol.VNetPeerOffer
	secret     []byte
	connection *quicgo.Conn
	active     bool
	dialing    bool
}

type peerFlowRoute struct {
	direct     bool
	generation uint64
	expiresAt  time.Time
}

// PeerEndpoint owns one client's dedicated UDP socket and direct QUIC paths.
type PeerEndpoint struct {
	context     context.Context
	cancel      context.CancelFunc
	clientID    string
	sessionID   string
	virtualIP   netip.Addr
	mtu         uint16
	connection  *net.UDPConn
	transport   *quicgo.Transport
	listener    *quicgo.Listener
	certificate tls.Certificate
	fingerprint string
	status      func(protocol.VNetPeerStatus) error
	receive     func([]byte) error
	openFlow    func(uint64, string, Flow) error

	mutex      sync.Mutex
	offers     map[uint64]*peerOfferState
	activeByIP map[netip.Addr]*peerOfferState
	flows      map[[13]byte]peerFlowRoute
	waitGroup  sync.WaitGroup
	closeOnce  sync.Once
}

// SetFlowOpener registers the control-plane fallback authorization callback.
func (endpoint *PeerEndpoint) SetFlowOpener(opener func(uint64, string, Flow) error) {
	endpoint.mutex.Lock()
	endpoint.openFlow = opener
	endpoint.mutex.Unlock()
}

// NewPeerEndpoint binds the mandatory P+1 UDP socket.
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
	address, err := net.ResolveUDPAddr("udp4", bindAddress)
	if err != nil {
		return nil, fmt.Errorf("resolve VNet P2P UDP address: %w", err)
	}
	connection, err := net.ListenUDP("udp4", address)
	if err != nil {
		return nil, fmt.Errorf("bind VNet P2P UDP address %q: %w", bindAddress, err)
	}
	certificate, fingerprint, err := newPeerCertificate(clientID)
	if err != nil {
		connection.Close()
		return nil, err
	}
	parsedIP, err := netip.ParseAddr(virtualIP)
	if err != nil || !parsedIP.Is4() {
		connection.Close()
		return nil, errors.New("invalid VNet P2P virtual address")
	}
	ctx, cancel := context.WithCancel(parent)
	endpoint := &PeerEndpoint{
		context: ctx, cancel: cancel, clientID: clientID, sessionID: sessionID,
		virtualIP: parsedIP, mtu: mtu, connection: connection,
		certificate: certificate, fingerprint: fingerprint, status: status, receive: receive,
		offers: make(map[uint64]*peerOfferState), activeByIP: make(map[netip.Addr]*peerOfferState),
		flows: make(map[[13]byte]peerFlowRoute),
	}
	endpoint.transport = &quicgo.Transport{Conn: connection}
	listener, err := endpoint.transport.Listen(endpoint.baseServerTLS(), endpoint.quicConfig())
	if err != nil {
		endpoint.transport.Close()
		cancel()
		return nil, fmt.Errorf("listen for VNet peer QUIC: %w", err)
	}
	endpoint.listener = listener
	endpoint.waitGroup.Go(endpoint.acceptConnections)
	endpoint.waitGroup.Go(endpoint.readSignals)
	return endpoint, nil
}

// Fingerprint returns the ephemeral certificate fingerprint.
func (endpoint *PeerEndpoint) Fingerprint() string { return endpoint.fingerprint }

// HostCandidates returns bounded IPv4 host candidates using the bound port.
func (endpoint *PeerEndpoint) HostCandidates() []string {
	port := endpoint.connection.LocalAddr().(*net.UDPAddr).Port
	interfaces, _ := net.Interfaces()
	candidates := make([]string, 0, min(len(interfaces), peerMaximumCandidates))
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
			if len(candidates) == peerMaximumCandidates {
				return candidates
			}
		}
	}
	return candidates
}

// Register sends an authenticated mapping registration to the coordinator.
func (endpoint *PeerEndpoint) Register(serverAddress string, ticket string) error {
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
	secret, err := base64.RawURLEncoding.DecodeString(offer.PairTicket)
	peerIP, ipError := netip.ParseAddr(offer.PeerVirtualIP)
	if err != nil || len(secret) < 16 || ipError != nil || !peerIP.Is4() ||
		offer.PeerGeneration == 0 || offer.PeerClientID == "" || offer.PeerClientID == endpoint.clientID ||
		(offer.Role != protocol.VNetPeerRoleClient && offer.Role != protocol.VNetPeerRoleServer) ||
		offer.ExpiresAtUnixMS <= time.Now().UnixMilli() || len(offer.Candidates) > peerMaximumCandidates {
		return errors.New("invalid VNet peer offer")
	}
	state := &peerOfferState{offer: offer, secret: secret}
	endpoint.mutex.Lock()
	if previous := endpoint.offers[offer.PeerGeneration]; previous != nil {
		endpoint.mutex.Unlock()
		return errors.New("duplicate VNet peer offer")
	}
	endpoint.offers[offer.PeerGeneration] = state
	endpoint.mutex.Unlock()
	hostCandidates := make([]protocol.VNetPeerCandidate, 0, len(offer.Candidates))
	reflexiveCandidates := make([]protocol.VNetPeerCandidate, 0, 1)
	for _, candidate := range offer.Candidates {
		if candidate.Type == "host" {
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
			connected := state.connection != nil
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
	if state != nil && state.offer.PeerClientID == revocation.PeerClientID {
		delete(endpoint.offers, revocation.PeerGeneration)
		peerIP, _ := netip.ParseAddr(state.offer.PeerVirtualIP)
		if endpoint.activeByIP[peerIP] == state {
			delete(endpoint.activeByIP, peerIP)
		}
	}
	endpoint.mutex.Unlock()
	if state != nil && state.connection != nil {
		_ = state.connection.CloseWithError(peerApplicationErrorClose, "peer path revoked")
	}
}

// MarkRelay pins a flow to the center path before a direct path is ready.
func (endpoint *PeerEndpoint) MarkRelay(flow Flow, now time.Time) {
	key, ok := peerFlowKey(flow)
	if !ok {
		return
	}
	endpoint.mutex.Lock()
	endpoint.expireFlowsLocked(now)
	if _, exists := endpoint.flows[key]; !exists && len(endpoint.flows) < peerMaximumTrackedFlows {
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
	route, exists := endpoint.flows[key]
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
		if len(endpoint.flows) >= peerMaximumTrackedFlows || flow.Protocol == protocolTCP && !flow.IsTCPStart() {
			endpoint.mutex.Unlock()
			return false, nil
		}
		route = peerFlowRoute{direct: true, generation: state.offer.PeerGeneration}
		if endpoint.openFlow != nil {
			if err := endpoint.openFlow(state.offer.PeerGeneration, state.offer.PeerClientID, flow); err != nil {
				endpoint.mutex.Unlock()
				return false, err
			}
		}
	}
	if !route.direct || route.generation != state.offer.PeerGeneration {
		endpoint.mutex.Unlock()
		return false, nil
	}
	route.expiresAt = peerFlowExpiry(flow, now)
	endpoint.flows[key] = route
	connection := state.connection
	generation := state.offer.PeerGeneration
	if flow.IsTCPReset() {
		delete(endpoint.flows, key)
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

func (endpoint *PeerEndpoint) readSignals() {
	buffer := make([]byte, peerSignalMaximumSize)
	for {
		length, address, err := endpoint.transport.ReadNonQUICPacket(endpoint.context, buffer)
		if err != nil {
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
	if state.dialing || state.connection != nil || time.Now().UnixMilli() >= state.offer.ExpiresAtUnixMS {
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
			endpoint.mutex.Unlock()
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
	if endpoint.offers[state.offer.PeerGeneration] != state || state.connection != nil {
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
	route, exists := endpoint.flows[key]
	if !exists {
		if len(endpoint.flows) >= peerMaximumTrackedFlows ||
			(flow.Protocol == protocolTCP && !flow.IsTCPStart()) ||
			!peerPortAllowed(state.offer, flow.Protocol, flow.DestinationPort) {
			return false
		}
		route = peerFlowRoute{direct: true, generation: state.offer.PeerGeneration}
	}
	if !route.direct || route.generation != state.offer.PeerGeneration {
		return false
	}
	route.expiresAt = peerFlowExpiry(flow, now)
	endpoint.flows[key] = route
	if flow.IsTCPReset() {
		delete(endpoint.flows, key)
	}
	return true
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
	state.active = false
	for key, route := range endpoint.flows {
		if route.direct && route.generation == state.offer.PeerGeneration {
			route.direct = false
			route.generation = 0
			endpoint.flows[key] = route
		}
	}
	endpoint.mutex.Unlock()
	if endpoint.status != nil && endpoint.context.Err() == nil {
		_ = endpoint.status(protocol.VNetPeerStatus{
			PeerGeneration: state.offer.PeerGeneration, PeerClientID: state.offer.PeerClientID,
			State: protocol.VNetPeerStateFailed, Code: code,
		})
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

// Close releases the dedicated UDP socket and all peer connections.
func (endpoint *PeerEndpoint) Close() error {
	endpoint.closeOnce.Do(func() {
		endpoint.cancel()
		if endpoint.listener != nil {
			_ = endpoint.listener.Close()
		}
		endpoint.mutex.Lock()
		for _, state := range endpoint.offers {
			if state.connection != nil {
				_ = state.connection.CloseWithError(peerApplicationErrorClose, "peer endpoint closed")
			}
		}
		endpoint.mutex.Unlock()
		_ = endpoint.transport.Close()
	})
	endpoint.waitGroup.Wait()
	return nil
}

func newPeerCertificate(clientID string) (tls.Certificate, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate VNet peer key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate VNet peer serial: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "portway-vnet-peer-" + clientID},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("create VNet peer certificate: %w", err)
	}
	digest := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}, hex.EncodeToString(digest[:]), nil
}

func verifyPeerFingerprint(expected string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCertificates [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCertificates) != 1 {
			return errors.New("invalid VNet peer certificate chain")
		}
		digest := sha256.Sum256(rawCertificates[0])
		if !strings.EqualFold(hex.EncodeToString(digest[:]), expected) {
			return errors.New("VNet peer certificate fingerprint mismatch")
		}
		return nil
	}
}

func peerServerName(generation uint64) string { return fmt.Sprintf("p%x", generation) }

func parsePeerServerName(value string) (uint64, error) {
	if len(value) < 2 || value[0] != 'p' {
		return 0, errors.New("invalid VNet peer server name")
	}
	return strconv.ParseUint(value[1:], 16, 64)
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

func (endpoint *PeerEndpoint) expireFlowsLocked(now time.Time) {
	for key, route := range endpoint.flows {
		if !now.Before(route.expiresAt) {
			delete(endpoint.flows, key)
		}
	}
}
