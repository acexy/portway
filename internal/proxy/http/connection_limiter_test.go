package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func BenchmarkConnectionLimiterSaturated(b *testing.B) {
	for _, count := range []int{1, 128, 1024} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			limiter := NewConnectionLimiter(1)
			for range count {
				limiter.register(&stdhttp.Transport{})
			}
			release, err := limiter.acquire(context.Background())
			if err != nil {
				b.Fatal(err)
			}
			defer release()
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := limiter.acquire(context.Background()); !errors.Is(err, errConnectionCapacity) {
					b.Fatal(err)
				}
			}
		})
	}
}

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
	firstConnectionClosed := make(chan struct{})
	var closeOnce sync.Once
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
			return &limitedConnection{Conn: connection, release: func() {
				release()
				closeOnce.Do(func() { close(firstConnectionClosed) })
			}}, nil
		},
	}
	unregister := limiter.register(transport)
	defer unregister()
	defer transport.CloseIdleConnections()
	client := &stdhttp.Client{Transport: limiter.track(transport)}
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
	for range 3 {
		response, err = client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
	}
	if limiter.idle.Len() != 1 {
		t.Fatal("idle notifications were not deduplicated")
	}
	// Failed admission must not mark active-only pools for deferred closure.
	select {
	case <-firstConnectionClosed:
		t.Fatal("capacity rejection closed an active connection on return")
	default:
	}
	if len(limiter.slots) != 1 {
		t.Fatal("expected idle connection to hold global capacity")
	}
	release, err := limiter.acquire(context.Background())
	if err != nil {
		t.Fatalf("another domain could not reclaim idle capacity: %v", err)
	}
	release()
	unregister()
	if len(limiter.pools) != 0 || limiter.idle.Len() != 0 {
		t.Fatal("closed binding retained its pool registration")
	}
}
