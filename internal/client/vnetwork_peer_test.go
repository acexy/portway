package client

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/vnet"
)

func TestUserspaceOutputUsesBidirectionalDirectPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ready := make(chan protocol.VNetPeerStatus, 8)
	received := make(chan []byte, 2)
	addresses := make([]string, 2)
	endpoints := make([]*vnet.PeerEndpoint, 2)
	identities := []string{"client-a", "client-b"}
	ips := []string{"172.20.0.2", "172.20.0.3"}
	for index := range endpoints {
		reservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		addresses[index] = reservation.LocalAddr().String()
		_ = reservation.Close()
		endpoints[index], err = vnet.NewPeerEndpoint(ctx, addresses[index], identities[index], identities[index], ips[index], 1150,
			func(status protocol.VNetPeerStatus) error { ready <- status; return nil },
			func(packet []byte) error { received <- packet; return nil })
		if err != nil {
			t.Fatal(err)
		}
		defer endpoints[index].Close()
	}
	ticket := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for index := range endpoints {
		other := 1 - index
		role := protocol.VNetPeerRoleClient
		if index == 1 {
			role = protocol.VNetPeerRoleServer
		}
		if err := endpoints[index].ApplyOffer(protocol.VNetPeerOffer{
			PeerGeneration: 1, PeerClientID: identities[other], PeerVirtualIP: ips[other],
			PeerFingerprint: endpoints[other].Fingerprint(), PairTicket: ticket, Role: role,
			Candidates: []protocol.VNetPeerCandidate{{Type: "host", Address: addresses[other]}},
			InboundUDP: []protocol.VNetPeerPortRange{{Start: 53, End: 53}},
			ExpiresAtUnixMS: time.Now().Add(9 * time.Second).UnixMilli(),
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
			t.Fatal("peer handshake did not complete")
		}
	}
	for index, endpoint := range endpoints {
		if err := endpoint.Activate(protocol.VNetPeerActivate{PeerGeneration: 1, PeerClientID: identities[1-index]}); err != nil {
			t.Fatal(err)
		}
	}
	packet := make([]byte, 28)
	packet[0], packet[9] = 0x45, 17
	binary.BigEndian.PutUint16(packet[2:4], 28)
	copy(packet[12:16], []byte{172, 20, 0, 2})
	copy(packet[16:20], []byte{172, 20, 0, 3})
	binary.BigEndian.PutUint16(packet[20:22], 50000)
	binary.BigEndian.PutUint16(packet[22:24], 53)
	binary.BigEndian.PutUint16(packet[24:26], 8)
	for index := range endpoints {
		// No relay pool is installed: both output directions must use the peer.
		manager := &clientVNetManager{peerEndpoint: endpoints[index], assignment: lifecycleVNetAssignment()}
		if err := manager.sendUserspaceTCPPacket(packet); err != nil {
			t.Fatalf("userspace output bypassed direct routing: %v", err)
		}
		select {
		case <-received:
		case <-ctx.Done():
			t.Fatal("userspace packet was not delivered directly")
		}
		packet[15], packet[19] = packet[19], packet[15]
		binary.BigEndian.PutUint16(packet[20:22], 53)
		binary.BigEndian.PutUint16(packet[22:24], 50000)
	}
}
