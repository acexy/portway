package http

import (
	"context"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"
)

func TestConnectionLimiterBoundsAllBindings(t *testing.T) {
	limiter := NewConnectionLimiter(1)
	release, err := limiter.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := limiter.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("second acquisition error = %v, want context cancellation", err)
	}
	release()
	secondRelease, err := limiter.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondRelease()
}

func TestConnectionLimiterReclaimsIdlePoolWithoutClosingActiveRequest(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		writer.Write([]byte("response"))
	}))
	defer server.Close()
	limiter := NewConnectionLimiter(1)
	transport := &stdhttp.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			release, err := limiter.acquire(ctx)
			if err != nil {
				return nil, err
			}
			connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				release()
				return nil, err
			}
			return &limitedConnection{Conn: connection, release: release}, nil
		},
	}
	unregister := limiter.register(transport)
	defer unregister()
	defer transport.CloseIdleConnections()
	client := &stdhttp.Client{Transport: transport}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := limiter.acquire(context.Background()); !errors.Is(err, errConnectionCapacity) {
		t.Fatalf("active connection must keep its slot: %v", err)
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatalf("capacity pressure interrupted active response: %v", err)
	}
	response.Body.Close()
	// The earlier pressure closes this connection on return to the pool.
	// A fresh request clears that flag and leaves a genuine idle connection.
	response, err = client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(limiter.slots) != 1 {
		t.Fatal("expected idle connection to hold global capacity")
	}
	release, err := limiter.acquire(context.Background())
	if err != nil {
		t.Fatalf("another domain could not reclaim idle capacity: %v", err)
	}
	release()
	unregister()
	if len(limiter.pools) != 0 {
		t.Fatal("closed binding retained its pool registration")
	}
}
