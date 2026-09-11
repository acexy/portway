package vnet

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
)

func TestPoolBrokerActivatesCompletePoolAndTransfersPacket(t *testing.T) {
	broker := NewPoolBroker()
	authenticationContext := authentication.Context{
		Mode:     authentication.ModeGoverned,
		ClientID: "client-a",
	}
	spec := PoolSpec{
		ClientID:            "client-a",
		SessionID:           "session-a",
		TransportGeneration: 3,
		VirtualIP:           "172.20.0.2",
		PoolGeneration:      4,
		ChannelCount:        2,
		MTU:                 1280,
		Authentication:      authenticationContext,
	}
	offers, err := broker.Prepare(spec, time.Second)
	if err != nil {
		t.Fatalf("prepare pool: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peers := make([]net.Conn, len(offers))
	bindErrors := make(chan error, len(offers))
	activated := make(chan *Pool, 1)
	for index, offer := range offers {
		server, client := net.Pipe()
		peers[index] = client
		binding := protocol.BindVNetChannel{
			ClientID:            spec.ClientID,
			SessionID:           spec.SessionID,
			TransportGeneration: spec.TransportGeneration,
			VirtualIP:           spec.VirtualIP,
			PoolGeneration:      offer.PoolGeneration,
			ChannelIndex:        offer.ChannelIndex,
			ChannelCount:        offer.ChannelCount,
			Ticket:              offer.Ticket,
		}
		go func() {
			bindErrors <- broker.Bind(ctx, server, binding, authenticationContext, nil, func(pool *Pool) {
				activated <- pool
			})
		}()
	}
	var pool *Pool
	select {
	case pool = <-activated:
	case <-time.After(time.Second):
		t.Fatal("pool did not activate")
	}
	packet := testIPv4Packet(protocolUDP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 53)
	sendError := make(chan error, 1)
	go func() { sendError <- pool.Send(packet, 0) }()
	received, err := ReadPacket(peers[0], spec.MTU)
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	if len(received) != len(packet) {
		t.Fatalf("unexpected packet length %d", len(received))
	}
	if err := <-sendError; err != nil {
		t.Fatalf("send packet: %v", err)
	}
	cancel()
	for range offers {
		select {
		case <-bindErrors:
		case <-time.After(time.Second):
			t.Fatal("binding did not stop")
		}
	}
	for _, peer := range peers {
		peer.Close()
	}
}

func TestPoolBrokerRejectsTicketForDifferentIndex(t *testing.T) {
	broker := NewPoolBroker()
	spec := PoolSpec{
		ClientID: "client-a", SessionID: "session-a", VirtualIP: "172.20.0.2",
		PoolGeneration: 1, ChannelCount: 2, MTU: 1280,
	}
	offers, err := broker.Prepare(spec, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	binding := protocol.BindVNetChannel{
		ClientID: spec.ClientID, SessionID: spec.SessionID, VirtualIP: spec.VirtualIP,
		PoolGeneration: spec.PoolGeneration, ChannelIndex: 1, ChannelCount: spec.ChannelCount,
		Ticket: offers[0].Ticket,
	}
	if err := broker.Bind(context.Background(), server, binding, authentication.Context{}, nil, nil); err == nil {
		t.Fatal("ticket was accepted for a different channel index")
	}
}
