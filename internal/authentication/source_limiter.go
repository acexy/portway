package authentication

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

const (
	defaultMaximumTrackedSources = 4096
	defaultMaximumFailures       = 10
	defaultFailureWindow         = time.Minute
	defaultBlockDuration         = time.Minute
)

type sourceFailureEntry struct {
	address      netip.Addr
	windowStart  time.Time
	failures     int
	blockedUntil time.Time
	element      *list.Element
}

// SourceFailureLimiter bounds authentication attempts by normalized source IP.
// State is itself bounded and successful authentication forgets prior failures.
type SourceFailureLimiter struct {
	mutex           sync.Mutex
	entries         map[netip.Addr]*sourceFailureEntry
	recency         list.List
	maximumSources  int
	maximumFailures int
	window          time.Duration
	blockDuration   time.Duration
	now             func() time.Time
}

// NewSourceFailureLimiter creates the server-wide default authentication limiter.
func NewSourceFailureLimiter() *SourceFailureLimiter {
	return newSourceFailureLimiter(
		defaultMaximumTrackedSources,
		defaultMaximumFailures,
		defaultFailureWindow,
		defaultBlockDuration,
	)
}

func newSourceFailureLimiter(
	maximumSources int,
	maximumFailures int,
	window time.Duration,
	blockDuration time.Duration,
) *SourceFailureLimiter {
	return &SourceFailureLimiter{
		entries:         make(map[netip.Addr]*sourceFailureEntry),
		maximumSources:  maximumSources,
		maximumFailures: maximumFailures,
		window:          window,
		blockDuration:   blockDuration,
		now:             time.Now,
	}
}

// Allow reports whether authentication may start for the source.
func (limiter *SourceFailureLimiter) Allow(address netip.Addr) bool {
	if limiter == nil || !address.IsValid() {
		return false
	}
	address = address.Unmap()
	now := limiter.now()
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	entry := limiter.entries[address]
	if entry == nil {
		return true
	}
	limiter.recency.MoveToBack(entry.element)
	if now.Before(entry.blockedUntil) {
		return false
	}
	if now.Sub(entry.windowStart) >= limiter.window {
		limiter.removeLocked(entry)
	}
	return true
}

// RecordFailure accounts for one failed authentication attempt.
func (limiter *SourceFailureLimiter) RecordFailure(address netip.Addr) {
	if limiter == nil || !address.IsValid() {
		return
	}
	address = address.Unmap()
	now := limiter.now()
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	entry := limiter.entries[address]
	if entry == nil {
		for len(limiter.entries) >= limiter.maximumSources {
			oldest, _ := limiter.recency.Front().Value.(*sourceFailureEntry)
			limiter.removeLocked(oldest)
		}
		entry = &sourceFailureEntry{address: address, windowStart: now}
		entry.element = limiter.recency.PushBack(entry)
		limiter.entries[address] = entry
	} else {
		limiter.recency.MoveToBack(entry.element)
		if !now.Before(entry.blockedUntil) && now.Sub(entry.windowStart) >= limiter.window {
			entry.windowStart = now
			entry.failures = 0
			entry.blockedUntil = time.Time{}
		}
	}
	entry.failures++
	if entry.failures >= limiter.maximumFailures {
		entry.blockedUntil = now.Add(limiter.blockDuration)
	}
}

// RecordSuccess clears failure state for an authenticated source.
func (limiter *SourceFailureLimiter) RecordSuccess(address netip.Addr) {
	if limiter == nil || !address.IsValid() {
		return
	}
	address = address.Unmap()
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	if entry := limiter.entries[address]; entry != nil {
		limiter.removeLocked(entry)
	}
}

func (limiter *SourceFailureLimiter) removeLocked(entry *sourceFailureEntry) {
	if entry == nil {
		return
	}
	delete(limiter.entries, entry.address)
	limiter.recency.Remove(entry.element)
}
