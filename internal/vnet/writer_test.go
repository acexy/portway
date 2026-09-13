package vnet

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestPacketWriterBoundsQueueWait(t *testing.T) {
	connection, peer := net.Pipe()
	defer connection.Close()
	defer peer.Close()
	writer := NewPacketWriter(context.Background(), connection, 1280, 20*time.Millisecond)
	writer.gate <- struct{}{}
	result := make(chan error, 1)
	go func() { result <- writer.Send([]byte{1}) }()
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("queue timeout = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("write queue exceeded its deadline")
	}
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("failed writer left its stream open")
	}
}

func TestPacketWriterCancelsQueueWait(t *testing.T) {
	connection, peer := net.Pipe()
	defer connection.Close()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	writer := NewPacketWriter(ctx, connection, 1280, time.Hour)
	writer.gate <- struct{}{}
	cancel()
	if err := writer.Send([]byte{1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel queued write = %v", err)
	}
}
