package tcp

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestListenerAcceptsAndForwardsTCPVisitor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- listener.Serve(func(visitor net.Conn) {
			defer visitor.Close()
			payload := make([]byte, 4)
			if _, err := io.ReadFull(visitor, payload); err == nil {
				_, _ = visitor.Write(payload)
			}
		})
	}()
	visitor, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := visitor.Write([]byte("echo")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(visitor, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "echo" {
		t.Fatalf("response = %q", response)
	}
	visitor.Close()
	listener.Close()
	select {
	case err := <-serveErrors:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestTargetHandlerFactoryRejectsUnauthorizedTarget(t *testing.T) {
	factory := TargetHandlerFactory("127.0.0.1:1", time.Second, func() bool { return false })
	_, err := factory(context.Background())
	if err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("factory returned %v", err)
	}
}
