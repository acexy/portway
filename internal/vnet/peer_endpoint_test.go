package vnet

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"testing"
	"time"

	"github.com/acexy/portway/internal/protocol"
)

func TestPeerUDPAddress(t *testing.T) {
	address, err := PeerUDPAddress("127.0.0.1:7000", false)
	if err != nil || address != "127.0.0.1:7001" {
		t.Fatalf("peer address = %q, %v", address, err)
	}
	wildcard, err := PeerUDPAddress("example.test:7000", true)
	if err != nil || wildcard != "0.0.0.0:7001" {
		t.Fatalf("wildcard peer address = %q, %v", wildcard, err)
	}
	if _, err := PeerUDPAddress("127.0.0.1:65535", false); err == nil {
		t.Fatal("port 65535 was accepted")
	}
}

func TestPeerSignalAuthentication(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	encoded, err := EncodePeerSignal(PeerSignal{
		Kind: PeerSignalRegister, ClientID: "client-a", SessionID: "session-a",
	}, secret)
	if err != nil {
		t.Fatalf("encode signal: %v", err)
	}
	signal, err := ParsePeerSignal(encoded)
	if err != nil || signal.ClientID != "client-a" {
		t.Fatalf("parse signal: %+v, %v", signal, err)
	}
	if err := VerifyPeerSignal(encoded, secret); err != nil {
		t.Fatalf("verify signal: %v", err)
	}
	encoded[len(encoded)-1] ^= 1
	if err := VerifyPeerSignal(encoded, secret); err == nil {
		t.Fatal("tampered signal was accepted")
	}
}

func TestPeerEndpointRejectsInboundFlowOutsideActiveGeneration(t *testing.T) {
	state := &peerOfferState{offer: protocol.VNetPeerOffer{
		PeerGeneration: 1,
		InboundTCP:     []protocol.VNetPeerPortRange{{Start: 8080, End: 8080}},
	}}
	endpoint := &PeerEndpoint{
		offers: map[uint64]*peerOfferState{1: state},
		flows:  make(map[[13]byte]peerFlowRoute),
	}
	flow := Flow{
		Protocol: protocolTCP,
		SourceIP: netip.MustParseAddr("172.20.0.2"), SourcePort: 50000,
		DestinationIP: netip.MustParseAddr("172.20.0.3"), DestinationPort: 8080,
		TCPFlags: 0x02,
	}
	if endpoint.authorizeInbound(state, flow, time.Now()) {
		t.Fatal("inbound flow was accepted before peer activation")
	}
	state.active = true
	if !endpoint.authorizeInbound(state, flow, time.Now()) {
		t.Fatal("active inbound flow was rejected")
	}
	delete(endpoint.offers, 1)
	if endpoint.authorizeInbound(state, flow, time.Now()) {
		t.Fatal("revoked peer generation accepted an inbound flow")
	}
}

func TestPeerEndpointQUICDatagramRoundTrip(t *testing.T) {
	t.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readyA := make(chan protocol.VNetPeerStatus, 1)
	readyB := make(chan protocol.VNetPeerStatus, 1)
	received := make(chan []byte, 1)
	endpointA, err := NewPeerEndpoint(
		ctx, "127.0.0.1:0", "client-a", "session-a", "172.20.0.2", 1280,
		func(status protocol.VNetPeerStatus) error { readyA <- status; return nil },
		func([]byte) error { return nil },
	)
	if err != nil {
		t.Fatalf("create endpoint A: %v", err)
	}
	defer endpointA.Close()
	endpointB, err := NewPeerEndpoint(
		ctx, "127.0.0.1:0", "client-b", "session-b", "172.20.0.3", 1280,
		func(status protocol.VNetPeerStatus) error { readyB <- status; return nil },
		func(packet []byte) error { received <- packet; return nil },
	)
	if err != nil {
		t.Fatalf("create endpoint B: %v", err)
	}
	defer endpointB.Close()
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	ticket := base64.RawURLEncoding.EncodeToString(secret)
	expires := time.Now().Add(30 * time.Second).UnixMilli()
	generation := uint64(1)
	if err := endpointB.ApplyOffer(protocol.VNetPeerOffer{
		PeerGeneration: generation, PeerClientID: "client-a", PeerVirtualIP: "172.20.0.2",
		PeerFingerprint: endpointA.Fingerprint(), PairTicket: ticket,
		Role:       protocol.VNetPeerRoleServer,
		Candidates: []protocol.VNetPeerCandidate{{Address: endpointA.connection.LocalAddr().String(), Type: "host"}},
		InboundUDP: []protocol.VNetPeerPortRange{{Start: 9000, End: 9000}}, ExpiresAtUnixMS: expires,
	}); err != nil {
		t.Fatalf("apply endpoint B offer: %v", err)
	}
	if err := endpointA.ApplyOffer(protocol.VNetPeerOffer{
		PeerGeneration: generation, PeerClientID: "client-b", PeerVirtualIP: "172.20.0.3",
		PeerFingerprint: endpointB.Fingerprint(), PairTicket: ticket,
		Role:       protocol.VNetPeerRoleClient,
		Candidates: []protocol.VNetPeerCandidate{{Address: endpointB.connection.LocalAddr().String(), Type: "host"}},
		InboundUDP: []protocol.VNetPeerPortRange{{Start: 8000, End: 8000}}, ExpiresAtUnixMS: expires,
	}); err != nil {
		t.Fatalf("apply endpoint A offer: %v", err)
	}
	waitPeerReady := func(channel <-chan protocol.VNetPeerStatus) {
		t.Helper()
		select {
		case status := <-channel:
			if status.State != protocol.VNetPeerStateReady {
				t.Fatalf("peer state = %s", status.State)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("peer QUIC path did not become ready")
		}
	}
	waitPeerReady(readyA)
	waitPeerReady(readyB)
	if err := endpointA.Activate(protocol.VNetPeerActivate{PeerGeneration: generation, PeerClientID: "client-b"}); err != nil {
		t.Fatalf("activate endpoint A: %v", err)
	}
	if err := endpointB.Activate(protocol.VNetPeerActivate{PeerGeneration: generation, PeerClientID: "client-a"}); err != nil {
		t.Fatalf("activate endpoint B: %v", err)
	}
	packet := testIPv4Packet(protocolUDP, [4]byte{172, 20, 0, 2}, 8000, [4]byte{172, 20, 0, 3}, 9000)
	flow, _ := ParseIPv4(packet)
	sent, err := endpointA.Send(flow, packet, time.Now())
	if err != nil || !sent {
		t.Fatalf("send direct packet: sent=%t err=%v", sent, err)
	}
	select {
	case actual := <-received:
		actualFlow, parseError := ParseIPv4(actual)
		if parseError != nil || actualFlow.SourceIP != netip.MustParseAddr("172.20.0.2") {
			t.Fatalf("direct packet = %+v, %v", actualFlow, parseError)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("direct packet was not received")
	}
}
