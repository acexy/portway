package control

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/acexy/portway/internal/protocol"
)

type observedWriteConnection struct {
	net.Conn
	started chan struct{}
}

func (connection *observedWriteConnection) Write(packet []byte) (int, error) {
	select {
	case connection.started <- struct{}{}:
	default:
	}
	return connection.Conn.Write(packet)
}

func TestBoundedWriteIncludesGateWait(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	connection := &observedWriteConnection{local, make(chan struct{}, 1)}
	writer := NewWriter(connection)
	finished := make(chan error, 1)
	go func() { finished <- writer.Write(protocol.MessagePing, protocol.Heartbeat{Sequence: 1}) }()
	<-connection.started
	if err := writer.WriteUntil(time.Now().Add(20*time.Millisecond), protocol.MessagePing, protocol.Heartbeat{Sequence: 2}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("queued write did not expire: %v", err)
	}
	_ = writer.Close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt owner")
	}
}

func TestBoundedWriteClosesPartialStream(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	writer := NewWriter(local)
	err := writer.WriteUntil(time.Now().Add(20*time.Millisecond), protocol.MessagePing, protocol.Heartbeat{Sequence: 1})
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("blocked write: %v", err)
	}
	if _, err := remote.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("failed stream was not closed")
	}
}

func TestExpiredWriteDoesNotEmitBytes(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	writer := NewWriter(local)
	if err := writer.WriteUntil(time.Now().Add(-time.Second), protocol.MessagePing, protocol.Heartbeat{}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
}
