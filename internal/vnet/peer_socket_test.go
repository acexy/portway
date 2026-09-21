package vnet

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/protocol"
)

func TestPeerSocketReusesBindingWithFreshSessionAuthority(t *testing.T) {
	socket, err := NewPeerSocket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	connection, transport := socket.connection, socket.transport
	first, err := socket.NewEndpoint(context.Background(), "client-a", "old-session", "172.20.0.2", 1150, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := first.Fingerprint()
	if _, err := socket.NewEndpoint(context.Background(), "client-a", "overlap", "172.20.0.2", 1150, nil, nil); err == nil {
		t.Fatal("overlapping endpoints accepted")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	occupied, err := net.ListenUDP("udp4", connection.LocalAddr().(*net.UDPAddr))
	if err == nil {
		occupied.Close()
		t.Fatal("session close released process UDP binding")
	}
	second, err := socket.NewEndpoint(context.Background(), "client-a", "new-session", "172.20.0.4", 1100, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.connection != connection || second.transport != transport {
		t.Fatal("reconnect replaced socket or transport")
	}
	if second.Fingerprint() == fingerprint || second.sessionID != "new-session" || len(second.offers) != 0 || len(second.flows) != 0 {
		t.Fatal("session inherited old identity or state")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if socket.endpoint != second || !socket.Healthy() {
		t.Fatal("late old close affected replacement")
	}
	if err := first.ApplyOffer(protocol.VNetPeerOffer{}); err == nil {
		t.Fatal("retired endpoint accepted work")
	}
	collector, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	secret := make([]byte, 32)
	secret[0] = 7
	if err := second.Register(collector.LocalAddr().String(), base64.RawURLEncoding.EncodeToString(secret)); err != nil {
		t.Fatal(err)
	}
	_ = collector.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, peerSignalMaximumSize)
	count, source, err := collector.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	signal, err := ParsePeerSignal(buffer[:count])
	if err != nil || signal.SessionID != "new-session" || signal.Fingerprint != second.Fingerprint() {
		t.Fatalf("registration did not use new session: %v", err)
	}
	if VerifyPeerSignal(buffer[:count], secret) != nil || source.Port != connection.LocalAddr().(*net.UDPAddr).Port {
		t.Fatal("registration changed socket or used wrong credential")
	}
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if second.context.Err() == nil {
		t.Fatal("owner close retained active endpoint")
	}
	replacement, err := net.ListenUDP("udp4", connection.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("owner close retained UDP binding: %v", err)
	}
	replacement.Close()
}

func TestPeerSocketReconnectionRebuildsDirectPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	firstSocket, err := NewPeerSocket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer firstSocket.Close()
	secondSocket, err := NewPeerSocket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer secondSocket.Close()
	packet := testIPv4Packet(protocolUDP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 53)
	flow, _ := ParseIPv4(packet)
	for iteration := range 2 {
		ready := make(chan protocol.VNetPeerStatus, 8)
		delivered := make(chan struct{}, 4)
		report := func(status protocol.VNetPeerStatus) error { ready <- status; return nil }
		first, err := firstSocket.NewEndpoint(ctx, "client-a", fmt.Sprint("session-a-", iteration), "172.20.0.2", 1150, report, nil)
		if err != nil {
			t.Fatal(err)
		}
		second, err := secondSocket.NewEndpoint(ctx, "client-b", fmt.Sprint("session-b-", iteration), "172.20.0.3", 1150, report, func([]byte) error { delivered <- struct{}{}; return nil })
		if err != nil {
			t.Fatal(err)
		}
		secret := make([]byte, 32)
		secret[0] = byte(iteration + 1)
		ticket := base64.RawURLEncoding.EncodeToString(secret)
		endpoints := []*PeerEndpoint{first, second}
		for index, endpoint := range endpoints {
			peer := endpoints[1-index]
			role := protocol.VNetPeerRoleClient
			if index == 1 {
				role = protocol.VNetPeerRoleServer
			}
			if err := endpoint.ApplyOffer(protocol.VNetPeerOffer{PeerGeneration: 1, PeerClientID: peer.clientID, PeerVirtualIP: peer.virtualIP.String(), PeerFingerprint: peer.Fingerprint(), PairTicket: ticket, Role: role,
				Candidates: []protocol.VNetPeerCandidate{{Address: peer.connection.LocalAddr().String(), Type: "host"}}, InboundUDP: []protocol.VNetPeerPortRange{{Start: 53, End: 53}}, ExpiresAtUnixMS: time.Now().Add(8 * time.Second).UnixMilli(),
			}); err != nil {
				t.Fatal(err)
			}
		}
		for range 2 {
			select {
			case status := <-ready:
				if status.State != protocol.VNetPeerStateReady {
					t.Fatalf("peer failed: %s", status.Code)
				}
			case <-ctx.Done():
				t.Fatal("peer did not become ready")
			}
		}
		for index, endpoint := range endpoints {
			if err := endpoint.Activate(protocol.VNetPeerActivate{PeerGeneration: 1, PeerClientID: endpoints[1-index].clientID}); err != nil {
				t.Fatal(err)
			}
		}
		first.mutex.Lock()
		oldState := first.offers[1]
		oldConnection := oldState.connection
		first.mutex.Unlock()
		if sent, err := first.Send(flow, packet, time.Now()); !sent || err != nil {
			t.Fatalf("direct send failed: %v", err)
		}
		select {
		case <-delivered:
		case <-ctx.Done():
			t.Fatal("new session direct packet not delivered")
		}
		first.Close()
		second.Close()
		select {
		case <-oldConnection.Context().Done():
		case <-ctx.Done():
			t.Fatal("old QUIC connection retained")
		}
		if first.authorizeInbound(oldState, flow, time.Now()) {
			t.Fatal("closed session retained direct authority")
		}
	}
}

func TestPeerSocketFailureRequiresNewBinding(t *testing.T) {
	socket, err := NewPeerSocket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	endpoint, err := socket.NewEndpoint(context.Background(), "client-a", "session", "172.20.0.2", 1150, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = socket.connection.Close()
	stopped := make(chan struct{})
	go func() { endpoint.waitGroup.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("failed UDP readers did not stop")
	}
	if socket.Healthy() {
		t.Fatal("broken binding reported healthy")
	}
	endpoint.Close()
	if _, err := socket.NewEndpoint(context.Background(), "client-a", "next", "172.20.0.2", 1150, nil, nil); err == nil {
		t.Fatal("broken socket accepted new session")
	}
}
