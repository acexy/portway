package vnet

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type observedPacketConnection struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (connection *observedPacketConnection) Write(payload []byte) (int, error) {
	connection.once.Do(func() { close(connection.started) })
	return connection.Conn.Write(payload)
}

func queuedTestPool(t *testing.T) (*Pool, net.Conn, <-chan struct{}) {
	t.Helper()
	connection, peer := net.Pipe()
	observed := &observedPacketConnection{Conn: connection, started: make(chan struct{})}
	pool := activatePendingPool(&pendingPool{
		spec:     PoolSpec{ChannelCount: 1, MTU: 1150, WriteTimeout: time.Minute},
		channels: []pendingChannel{{connection: observed, ready: true}}, done: make(chan struct{}),
	})
	t.Cleanup(func() { pool.Close(); peer.Close() })
	return pool, peer, observed.started
}

func TestQueuedPoolBoundsMemoryAndIsolatesSlowDestination(t *testing.T) {
	slow, _, started := queuedTestPool(t)
	fast, peer, _ := queuedTestPool(t)
	packet := testIPv4Packet(protocolUDP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 53)
	if err := slow.Enqueue(packet, 0, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("slow write did not start")
	}
	for range poolQueuedPackets {
		if err := slow.Enqueue(packet, 0, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := slow.Enqueue(packet, 0, nil); !errors.Is(err, ErrPacketQueueFull) {
		t.Fatalf("queue overflow: %v", err)
	}
	if err := fast.Enqueue(packet, 0, nil); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := ReadPacket(peer, 1150); err != nil {
		t.Fatalf("slow peer blocked independent delivery: %v", err)
	}
	if err := slow.Close(); err != nil {
		t.Fatal(err)
	}
	if len(slow.queues[0]) != 0 {
		t.Fatal("closed pool retained queued payloads")
	}
}

func TestQueuedPoolRechecksAuthorization(t *testing.T) {
	pool, peer, started := queuedTestPool(t)
	packet := testIPv4Packet(protocolUDP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 53)
	if err := pool.Enqueue(packet, 0, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("write did not start")
	}
	rechecked := make(chan struct{})
	if err := pool.Enqueue(packet, 0, func() bool { close(rechecked); return false }); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := ReadPacket(peer, 1150); err != nil {
		t.Fatal(err)
	}
	select {
	case <-rechecked:
	case <-time.After(time.Second):
		t.Fatal("queued policy not checked")
	}
	// Only the new authorized packet may appear after the revoked queue entry.
	packet[1] = 4
	if err := pool.Enqueue(packet, 0, nil); err != nil {
		t.Fatal(err)
	}
	received, err := ReadPacket(peer, 1150)
	if err != nil {
		t.Fatal(err)
	}
	if received[1] != 4 {
		t.Fatal("revoked queued packet was delivered")
	}
}
