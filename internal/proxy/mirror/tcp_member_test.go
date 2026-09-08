package mirror

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestMirrorTCPMemberCancellationReleasesBlockedWrite(t *testing.T) {
	connection, peer := net.Pipe()
	defer peer.Close()
	member := &tcpMember{
		connection: connection, queue: make(chan []byte, 1),
		done: make(chan struct{}), stopped: make(chan struct{}),
	}
	member.queue <- []byte("blocked")
	go member.writeLoop(context.Background())
	member.close()
	select {
	case <-member.done:
	case <-time.After(time.Second):
		t.Fatal("closed member retained its writer")
	}
}
