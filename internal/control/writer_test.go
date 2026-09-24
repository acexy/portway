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
	started  chan struct{}
	deadline chan time.Time
}

func (connection *observedWriteConnection) Write(packet []byte) (int, error) {
	select {
	case connection.started <- struct{}{}:
	default:
	}
	return connection.Conn.Write(packet)
}

func (connection *observedWriteConnection) SetWriteDeadline(deadline time.Time) error {
	if connection.deadline != nil && !deadline.IsZero() {
		connection.deadline <- deadline
	}
	return connection.Conn.SetWriteDeadline(deadline)
}

func TestDefaultWriteBoundsNetworkIO(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	connection := &observedWriteConnection{Conn: local, started: make(chan struct{}, 1), deadline: make(chan time.Time, 1)}
	writer := NewWriter(connection)
	finished := make(chan error, 1)
	go func() { finished <- writer.Write(protocol.MessagePing, protocol.Heartbeat{Sequence: 1}) }()
	select {
	case deadline := <-connection.deadline:
		remaining := time.Until(deadline)
		if remaining <= 0 || remaining > writeTimeout {
			t.Fatalf("unexpected default write deadline: %s", remaining)
		}
	case <-time.After(time.Second):
		t.Fatal("default write did not set a deadline")
	}
	_ = writer.Close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt default write")
	}
}

func TestRequestWriteUntilClosesPartialStream(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	writer := NewWriter(local)
	err := writer.writeUntil(time.Now().Add(20*time.Millisecond), protocol.MessagePing, "request-id", protocol.Heartbeat{Sequence: 1})
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("blocked request write: %v", err)
	}
	if _, err := remote.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("failed request stream was not closed")
	}
}

func TestBoundedWriteIncludesGateWait(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	connection := &observedWriteConnection{Conn: local, started: make(chan struct{}, 1)}
	writer := NewWriter(connection)
	finished := make(chan error, 1)
	go func() { finished <- writer.Write(protocol.MessagePing, protocol.Heartbeat{Sequence: 1}) }()
	<-connection.started
	if err := writer.WriteUntil(time.Now().Add(20*time.Millisecond), protocol.MessagePing, protocol.Heartbeat{Sequence: 2}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("queued write did not expire: %v", err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("queued write timeout did not interrupt owner")
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
