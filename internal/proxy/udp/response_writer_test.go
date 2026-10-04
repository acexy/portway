package udp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type pipeResponseSocket struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (socket *pipeResponseSocket) WriteToUDPAddrPort(payload []byte, _ netip.AddrPort) (int, error) {
	socket.once.Do(func() { close(socket.started) })
	return socket.Write(payload)
}

func TestResponseCancellationPreservesSharedSocket(t *testing.T) {
	connection, peer := net.Pipe()
	defer connection.Close()
	defer peer.Close()
	socket := &pipeResponseSocket{Conn: connection, started: make(chan struct{})}
	writer := NewResponseWriter(socket)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- writer.Write(ctx, []byte("blocked"), netip.AddrPort{}, time.Minute) }()
	select {
	case <-socket.started:
	case <-time.After(time.Second):
		t.Fatal("write did not start")
	}
	queued, cancelQueued := context.WithCancel(context.Background())
	cancelQueued()
	if err := writer.Write(queued, nil, netip.AddrPort{}, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("queued cancellation: %v", err)
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("active cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled write retained socket ownership")
	}
	go func() { finished <- writer.Write(context.Background(), []byte("next"), netip.AddrPort{}, time.Second) }()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(peer, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "next" {
		t.Fatalf("unexpected response %q", buffer)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestResponseAdmissionTimeout(t *testing.T) {
	connection, peer := net.Pipe()
	defer connection.Close()
	defer peer.Close()
	writer := NewResponseWriter(&pipeResponseSocket{Conn: connection, started: make(chan struct{})})
	writer.gate <- struct{}{}
	if err := writer.Write(context.Background(), nil, netip.AddrPort{}, 10*time.Millisecond); err == nil {
		t.Fatal("unbounded admission")
	}
	<-writer.gate
}
