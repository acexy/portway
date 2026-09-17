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
		Mode:     authentication.ModeManaged,
		ClientID: "client-a",
	}
	spec := PoolSpec{
		ClientID:            "client-a",
		SessionID:           "session-a",
		TransportGeneration: 3,
		VirtualIP:           "172.20.0.2",
		PoolGeneration:      4,
		WriteTimeout:        time.Second,
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
		PoolGeneration: 1, ChannelCount: 2, MTU: 1280, WriteTimeout: time.Second,
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

func TestPoolSendTimesOutBlockedTarget(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	pool := &Pool{
		spec:     PoolSpec{MTU: 1280, WriteTimeout: 20 * time.Millisecond},
		channels: []net.Conn{server},
		writers:  []*PacketWriter{NewPacketWriter(context.Background(), server, 1280, 20*time.Millisecond)},
		done:     make(chan struct{}),
	}
	if err := pool.Send([]byte{1, 2, 3}, 0); err == nil {
		t.Fatal("expected blocked VNet target write to time out")
	}
	select {
	case <-pool.done:
	default:
		t.Fatal("failed target pool remained active")
	}
}

func TestPoolRemovalPreservesReplacementGeneration(t *testing.T) {
	broker := NewPoolBroker()
	defer broker.Close()
	spec := PoolSpec{
		ClientID: "client-a", SessionID: "session-a", VirtualIP: "172.20.0.2",
		PoolGeneration: 2, ChannelCount: 1, MTU: 1280, WriteTimeout: time.Second,
	}
	if _, err := broker.Prepare(spec, time.Minute); err != nil {
		t.Fatal(err)
	}
	broker.RemoveGeneration(spec.ClientID, spec.SessionID, 1)
	if broker.pending[spec.ClientID] == nil {
		t.Fatal("old cleanup removed replacement tickets")
	}
	connection, peer := net.Pipe()
	defer peer.Close()
	pool := &Pool{spec: spec, channels: []net.Conn{connection}, done: make(chan struct{})}
	broker.active[spec.ClientID] = pool
	broker.RemoveGeneration(spec.ClientID, spec.SessionID, 1)
	if current, ok := broker.Active(spec.ClientID); !ok || current != pool {
		t.Fatal("old cleanup removed replacement active pool")
	}
	broker.RemoveGeneration(spec.ClientID, spec.SessionID, 2)
	if _, ok := broker.Active(spec.ClientID); ok || broker.pending[spec.ClientID] != nil {
		t.Fatal("matching generation was not removed")
	}
}

func TestBlockedPoolDoesNotDelayIndependentPool(t *testing.T) {
	blockedServer, blockedPeer := net.Pipe()
	defer blockedPeer.Close()
	blocked := &Pool{
		spec:     PoolSpec{MTU: 1280, WriteTimeout: 50 * time.Millisecond},
		channels: []net.Conn{blockedServer},
		writers:  []*PacketWriter{NewPacketWriter(context.Background(), blockedServer, 1280, 50*time.Millisecond)},
		done:     make(chan struct{}),
	}
	fastServer, fastPeer := net.Pipe()
	defer fastPeer.Close()
	fast := &Pool{
		spec:     PoolSpec{MTU: 1280, WriteTimeout: time.Second},
		channels: []net.Conn{fastServer},
		writers:  []*PacketWriter{NewPacketWriter(context.Background(), fastServer, 1280, time.Second)},
		done:     make(chan struct{}),
	}
	packet := []byte{1, 2, 3}
	blockedResult := make(chan error, 1)
	go func() { blockedResult <- blocked.Send(packet, 0) }()
	fastResult := make(chan error, 1)
	go func() { fastResult <- fast.Send(packet, 0) }()
	if _, err := ReadPacket(fastPeer, 1280); err != nil {
		t.Fatalf("read independent pool: %v", err)
	}
	select {
	case err := <-fastResult:
		if err != nil {
			t.Fatalf("independent pool failed: %v", err)
		}
	case <-time.After(25 * time.Millisecond):
		t.Fatal("blocked pool delayed independent pool")
	}
	if err := <-blockedResult; err == nil {
		t.Fatal("blocked pool did not time out")
	}
	fast.Close()
}
