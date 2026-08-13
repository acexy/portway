package http

import (
	"context"
	"errors"
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
