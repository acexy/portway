package vnet

import (
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/acexy/portway/internal/protocol"
)

func TestPeerLANHandshakeFailureTriesPublicCandidate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	secret := make([]byte, 32)
	ticket := base64.RawURLEncoding.EncodeToString(secret)
	blackhole, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			count, address, err := blackhole.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			signal, err := ParsePeerSignal(buffer[:count])
			if err != nil || signal.Kind != PeerSignalProbe {
				continue
			}
			ack, _ := EncodePeerSignal(PeerSignal{Kind: PeerSignalProbeAck, ClientID: "client-b",
				PeerClientID: "client-a", PeerGeneration: 1}, secret)
			_, _ = blackhole.WriteToUDP(ack, address)
		}
	}()
	defer func() { _ = blackhole.Close(); <-done }()
	ready := make(chan protocol.VNetPeerStatus, 8)
	report := func(status protocol.VNetPeerStatus) error { ready <- status; return nil }
	first, err := NewPeerEndpoint(ctx, "127.0.0.1:0", "client-a", "session-a", "172.20.0.2", 1150, report, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewPeerEndpoint(ctx, "127.0.0.1:0", "client-b", "session-b", "172.20.0.3", 1150, report, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	expires := time.Now().Add(13 * time.Second).UnixMilli()
	if err := second.ApplyOffer(protocol.VNetPeerOffer{PeerGeneration: 1, PeerClientID: "client-a",
		PeerVirtualIP: "172.20.0.2", PeerFingerprint: first.Fingerprint(), PairTicket: ticket,
		Role: protocol.VNetPeerRoleServer, ExpiresAtUnixMS: expires,
		Candidates: []protocol.VNetPeerCandidate{{Type: "host", Address: first.connection.LocalAddr().String()}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := first.ApplyOffer(protocol.VNetPeerOffer{PeerGeneration: 1, PeerClientID: "client-b",
		PeerVirtualIP: "172.20.0.3", PeerFingerprint: second.Fingerprint(), PairTicket: ticket,
		Role: protocol.VNetPeerRoleClient, ExpiresAtUnixMS: expires,
		Candidates: []protocol.VNetPeerCandidate{
			{Type: "host", Address: blackhole.LocalAddr().String()},
			{Type: "server_reflexive", Address: second.connection.LocalAddr().String()},
		},
	}); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		select {
		case status := <-ready:
			if status.State != protocol.VNetPeerStateReady {
				t.Fatalf("public fallback failed: %s", status.Code)
			}
		case <-ctx.Done():
			t.Fatal("LAN handshake failure suppressed the public candidate")
		}
	}
}

func TestPeerCloseReleasesUDPSocket(t *testing.T) {
	endpoint, err := NewPeerEndpoint(context.Background(), "127.0.0.1:0", "client-a", "session-a", "172.20.0.2", 1150, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	address := endpoint.connection.LocalAddr().(*net.UDPAddr)
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.ListenUDP("udp4", address)
	if err != nil {
		t.Fatalf("closed endpoint retained its UDP port: %v", err)
	}
	_ = replacement.Close()
}

func TestPeerRevokePreservesRelayFlowAndRejectsOldGeneration(t *testing.T) {
	now := time.Unix(100, 0)
	flow := Flow{Protocol: protocolUDP, SourceIP: netip.MustParseAddr("172.20.0.2"),
		DestinationIP: netip.MustParseAddr("172.20.0.3"), SourcePort: 50000, DestinationPort: 8080}
	key, _ := peerFlowKey(flow)
	state := &peerOfferState{active: true, offer: protocol.VNetPeerOffer{
		PeerGeneration: 1, PeerClientID: "client-a", PeerVirtualIP: flow.SourceIP.String(),
	}}
	endpoint := &PeerEndpoint{offers: map[uint64]*peerOfferState{1: state},
		activeByIP: map[netip.Addr]*peerOfferState{flow.SourceIP: state},
		flows: map[[13]byte]peerFlowRoute{key: {direct: true, generation: 1, expiresAt: now.Add(time.Minute)}},
	}
	endpoint.Revoke(protocol.VNetPeerRevoke{PeerGeneration: 1, PeerClientID: "other"})
	if !state.active {
		t.Fatal("unrelated revocation disabled the peer")
	}
	endpoint.Revoke(protocol.VNetPeerRevoke{PeerGeneration: 1, PeerClientID: "client-a"})
	if endpoint.flows[key].direct || endpoint.flows[key].generation != 0 || state.active {
		t.Fatal("revocation did not atomically return the flow to relay")
	}
	if endpoint.authorizeInbound(state, flow, now) {
		t.Fatal("revoked generation accepted another packet")
	}
}

func TestDirectActivityRenewsCenterAuthorizationForLongLivedFlow(t *testing.T) {
	router := testRouter(t)
	now := time.Unix(100, 0)
	opener := Flow{Protocol: protocolTCP, SourceIP: netip.MustParseAddr("172.20.0.2"),
		DestinationIP: netip.MustParseAddr("172.20.0.3"), SourcePort: 50000, DestinationPort: 8080, TCPFlags: 2}
	if _, err := router.AuthorizePeerFlow("client-a", opener, now); err != nil {
		t.Fatal(err)
	}
	key, _ := peerFlowKey(opener)
	state := &peerOfferState{active: true, offer: protocol.VNetPeerOffer{PeerGeneration: 1, PeerClientID: "client-b"}}
	endpoint := &PeerEndpoint{virtualIP: opener.SourceIP, offers: map[uint64]*peerOfferState{1: state},
		flows: map[[13]byte]peerFlowRoute{key: {direct: true, generation: 1, opener: opener, expiresAt: now.Add(peerTCPFlowIdle)}},
	}
	renewals := 0
	endpoint.SetFlowOpener(func(generation uint64, peerID string, flow Flow) error {
		if generation != 1 || peerID != "client-b" || flow != opener {
			t.Fatal("renewal changed the original authorization direction")
		}
		renewals++
		_, err := router.AuthorizePeerFlow("client-a", flow, now)
		return err
	})
	reply := opener
	reply.SourceIP, reply.DestinationIP = opener.DestinationIP, opener.SourceIP
	reply.SourcePort, reply.DestinationPort = opener.DestinationPort, opener.SourcePort
	reply.TCPFlags = 0x10
	for index := 0; index < 61; index++ {
		now = now.Add(10 * time.Second)
		if !endpoint.authorizeInbound(state, reply, now) {
			t.Fatal("active incoming direct flow was rejected")
		}
	}
	if renewals != 31 {
		t.Fatalf("renewal frequency is not bounded: %d", renewals)
	}
	packet := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 3}, 8080, [4]byte{172, 20, 0, 2}, 50000)
	packet[33] = 0x10
	if _, err := router.RouteClientPacket("client-b", packet, now); err != nil {
		t.Fatalf("long-lived direct flow could not fall back: %v", err)
	}
	configuration := testVNetConfiguration()
	configuration.Nodes[1].Ports.TCP.PortRanges = nil
	if err := router.ApplyPolicy(configuration); err != nil {
		t.Fatal(err)
	}
	now = now.Add(peerFlowRenewInterval)
	if endpoint.authorizeInbound(state, reply, now) {
		t.Fatal("renewal bypassed tightened center policy")
	}
}

func TestPeerFlowExpiryIsCheckedBetweenCleanupTicks(t *testing.T) {
	now := time.Unix(100, 0)
	key := [13]byte{1}
	endpoint := &PeerEndpoint{nextCleanup: now.Add(time.Second),
		flows: map[[13]byte]peerFlowRoute{key: {direct: true, expiresAt: now}},
	}
	endpoint.expireFlowsLocked(now)
	if len(endpoint.flows) != 1 {
		t.Fatal("cleanup ran again before its next tick")
	}
	if _, exists := endpoint.flowLocked(key, now); exists {
		t.Fatal("expired flow was authorized between cleanup ticks")
	}
}
