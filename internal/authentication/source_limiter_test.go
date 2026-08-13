package authentication

import (
	"net/netip"
	"testing"
	"time"
)

func TestSourceFailureLimiterBlocksAndRecovers(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := newSourceFailureLimiter(2, 2, time.Minute, 2*time.Minute)
	limiter.now = func() time.Time { return now }
	address := netip.MustParseAddr("192.0.2.1")
	limiter.RecordFailure(address)
	if !limiter.Allow(address) {
		t.Fatal("source was blocked before reaching the failure threshold")
	}
	limiter.RecordFailure(address)
	if limiter.Allow(address) {
		t.Fatal("source remained allowed after reaching the failure threshold")
	}
	now = now.Add(2 * time.Minute)
	if !limiter.Allow(address) {
		t.Fatal("source did not recover after the block duration")
	}
}

func TestSourceFailureLimiterBoundsStateAndClearsSuccess(t *testing.T) {
	limiter := newSourceFailureLimiter(1, 2, time.Minute, time.Minute)
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	limiter.RecordFailure(first)
	limiter.RecordFailure(second)
	if len(limiter.entries) != 1 {
		t.Fatalf("tracked source count = %d, want 1", len(limiter.entries))
	}
	limiter.RecordSuccess(second)
	if len(limiter.entries) != 0 {
		t.Fatal("successful authentication retained failure state")
	}
}
