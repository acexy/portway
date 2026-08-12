package udp

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestForwardCancellationReleasesBlockedConnections(t *testing.T) {
	stream, streamPeer := net.Pipe()
	local, localPeer := net.Pipe()
	defer streamPeer.Close()
	defer localPeer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Forward(ctx, stream, local, 65507, time.Second)
	}()
	cancel()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("UDP forwarding remained blocked after cancellation")
	}
	if _, err := stream.Write([]byte("closed")); err == nil {
		t.Fatal("stream remained writable after forwarding stopped")
	}
	if _, err := local.Write([]byte("closed")); err == nil {
		t.Fatal("local connection remained writable after forwarding stopped")
	}
}
