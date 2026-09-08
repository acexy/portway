package udp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestForwardLocalWriteTimeoutReleasesBothDirections(t *testing.T) {
	stream, streamPeer := net.Pipe()
	local, localPeer := net.Pipe()
	defer streamPeer.Close()
	defer localPeer.Close()
	result := make(chan error, 1)
	go func() {
		result <- Forward(context.Background(), stream, local, 1024, 20*time.Millisecond)
	}()
	if err := WriteDatagram(streamPeer, []byte("blocked local service"), 1024); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("expected local write timeout, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked local UDP write did not release forwarding")
	}
}

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
