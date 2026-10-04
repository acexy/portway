package token

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/protocol"
)

func TestServerCloseReleasesQueuedAuthenticatedStreams(t *testing.T) {
	for _, role := range []protocol.Role{protocol.RoleControl, protocol.RoleData} {
		t.Run(fmt.Sprint(role), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			server, err := NewServer(ctx, "127.0.0.1:0", testAuthenticationStore(t, "test-token-with-at-least-32-random-bytes"), 8)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			client, err := DialToken(ctx, server.listener.Addr().String(), "test-token-with-at-least-32-random-bytes", role)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			// Observe publication without transferring ownership through Accept.
			select {
			case queued := <-server.results:
				server.results <- queued
			case <-ctx.Done():
				t.Fatal("authentication was not published")
			}
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("queued client read = %v, want EOF", err)
			}
			if _, err := server.Accept(context.Background()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Accept after Close = %v", err)
			}
			if err := server.Close(); err != nil {
				t.Fatalf("repeated Close = %v", err)
			}
		})
	}
}

func TestServerClosePreservesTransferredStreamOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	server, err := NewServer(ctx, "127.0.0.1:0", testAuthenticationStore(t, "test-token-with-at-least-32-random-bytes"), 8)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := DialToken(ctx, server.listener.Addr().String(), "test-token-with-at-least-32-random-bytes", protocol.RoleData)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	inbound, err := server.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer inbound.Stream.Close()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = inbound.Stream.SetDeadline(time.Now().Add(time.Second))
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1)
	if _, err := io.ReadFull(inbound.Stream, payload); err != nil || payload[0] != 'x' {
		t.Fatalf("transferred stream lost ownership: payload=%q error=%v", payload, err)
	}
}
