package udp

import (
	"net/netip"
	"sync"
	"time"

	"github.com/acexy/portway/internal/config"
)

type rateCounter struct {
	window time.Time
	count  int
}

// Limiter owns global UDP association, rate, and queued-byte accounting.
type Limiter struct {
	configuration     config.UDPConfig
	mutex             sync.Mutex
	total             int
	pending           int
	queuedBytes       int
	clients           map[string]int
	pendingClients    map[string]int
	proxies           map[string]int
	pendingProxies    map[string]int
	sources           map[netip.Addr]int
	globalRate        rateCounter
	clientRates       map[string]rateCounter
	proxyRates        map[string]rateCounter
	rateCleanupWindow time.Time
}

// NewLimiter creates a process-scoped UDP limiter.
func NewLimiter(configuration config.UDPConfig) *Limiter {
	return &Limiter{
		configuration:  configuration,
		clients:        make(map[string]int),
		pendingClients: make(map[string]int),
		proxies:        make(map[string]int),
		pendingProxies: make(map[string]int),
		sources:        make(map[netip.Addr]int),
		clientRates:    make(map[string]rateCounter),
		proxyRates:     make(map[string]rateCounter),
	}
}

// AssociationLease owns all accounting for one UDP association.
type AssociationLease struct {
	limiter  *Limiter
	clientID string
	proxyKey string
	source   netip.Addr
	mutex    sync.Mutex
	pending  bool
	queued   int
	closed   bool
}

// Acquire reserves capacity for a pending association.
func (limiter *Limiter) Acquire(
	clientID string,
	proxyName string,
	source netip.Addr,
	now time.Time,
) (*AssociationLease, bool) {
	source = source.Unmap()
	proxyKey := clientID + "\x00" + proxyName
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	limiter.cleanupRates(now)
	if limiter.total >= limiter.configuration.MaxAssociations ||
		limiter.clients[clientID] >= limiter.configuration.MaxAssociationsPerClient ||
		limiter.proxies[proxyKey] >= limiter.configuration.MaxAssociationsPerProxy ||
		limiter.sources[source] >= limiter.configuration.MaxAssociationsPerSourceIP ||
		limiter.pending >= limiter.configuration.MaxPendingAssociations ||
		limiter.pendingClients[clientID] >= limiter.configuration.MaxPendingAssociationsPerClient ||
		limiter.pendingProxies[proxyKey] >= limiter.configuration.MaxPendingAssociationsPerProxy ||
		!rateAllowed(limiter.globalRate, now, limiter.configuration.MaxNewAssociationsPerSecond) ||
		!mapRateAllowed(limiter.clientRates, clientID, now, limiter.configuration.MaxNewAssociationsPerSecondPerClient) ||
		!mapRateAllowed(limiter.proxyRates, proxyKey, now, limiter.configuration.MaxNewAssociationsPerSecondPerProxy) {
		return nil, false
	}
	limiter.globalRate = incrementRate(limiter.globalRate, now)
	limiter.clientRates[clientID] = incrementRate(limiter.clientRates[clientID], now)
	limiter.proxyRates[proxyKey] = incrementRate(limiter.proxyRates[proxyKey], now)
	limiter.total++
	limiter.pending++
	limiter.clients[clientID]++
	limiter.pendingClients[clientID]++
	limiter.proxies[proxyKey]++
	limiter.pendingProxies[proxyKey]++
	limiter.sources[source]++
	return &AssociationLease{
		limiter:  limiter,
		clientID: clientID,
		proxyKey: proxyKey,
		source:   source,
		pending:  true,
	}, true
}

func (limiter *Limiter) cleanupRates(now time.Time) {
	window := now.Truncate(time.Second)
	if limiter.rateCleanupWindow.Equal(window) {
		return
	}
	limiter.rateCleanupWindow = window
	for key, counter := range limiter.clientRates {
		if !counter.window.Equal(window) {
			delete(limiter.clientRates, key)
		}
	}
	for key, counter := range limiter.proxyRates {
		if !counter.window.Equal(window) {
			delete(limiter.proxyRates, key)
		}
	}
}

func rateAllowed(counter rateCounter, now time.Time, limit int) bool {
	window := now.Truncate(time.Second)
	if !counter.window.Equal(window) {
		return limit > 0
	}
	return counter.count < limit
}

func mapRateAllowed(
	counters map[string]rateCounter,
	key string,
	now time.Time,
	limit int,
) bool {
	return rateAllowed(counters[key], now, limit)
}

func incrementRate(counter rateCounter, now time.Time) rateCounter {
	window := now.Truncate(time.Second)
	if !counter.window.Equal(window) {
		return rateCounter{window: window, count: 1}
	}
	counter.count++
	return counter
}

// Activate transitions a pending association to active accounting.
func (lease *AssociationLease) Activate() {
	lease.mutex.Lock()
	if lease.closed || !lease.pending {
		lease.mutex.Unlock()
		return
	}
	lease.pending = false
	lease.mutex.Unlock()

	lease.limiter.mutex.Lock()
	lease.limiter.pending--
	decrement(lease.limiter.pendingClients, lease.clientID)
	decrement(lease.limiter.pendingProxies, lease.proxyKey)
	lease.limiter.mutex.Unlock()
}

// ReserveQueue reserves queued payload bytes for this association.
func (lease *AssociationLease) ReserveQueue(size int) bool {
	lease.mutex.Lock()
	defer lease.mutex.Unlock()
	if lease.closed ||
		lease.queued+size > lease.limiter.configuration.MaxQueuedBytesPerAssociation {
		return false
	}
	lease.limiter.mutex.Lock()
	defer lease.limiter.mutex.Unlock()
	if lease.limiter.queuedBytes+size > lease.limiter.configuration.MaxQueuedBytes {
		return false
	}
	lease.queued += size
	lease.limiter.queuedBytes += size
	return true
}

// ReleaseQueue releases queued payload bytes.
func (lease *AssociationLease) ReleaseQueue(size int) {
	lease.mutex.Lock()
	if lease.closed {
		lease.mutex.Unlock()
		return
	}
	lease.limiter.mutex.Lock()
	lease.queued -= size
	lease.limiter.queuedBytes -= size
	lease.limiter.mutex.Unlock()
	lease.mutex.Unlock()
}

// Close releases all association accounting exactly once.
func (lease *AssociationLease) Close() {
	lease.mutex.Lock()
	if lease.closed {
		lease.mutex.Unlock()
		return
	}
	lease.closed = true
	pending := lease.pending
	queued := lease.queued
	lease.queued = 0
	lease.mutex.Unlock()

	lease.limiter.mutex.Lock()
	lease.limiter.total--
	decrement(lease.limiter.clients, lease.clientID)
	decrement(lease.limiter.proxies, lease.proxyKey)
	decrement(lease.limiter.sources, lease.source)
	if pending {
		lease.limiter.pending--
		decrement(lease.limiter.pendingClients, lease.clientID)
		decrement(lease.limiter.pendingProxies, lease.proxyKey)
	}
	lease.limiter.queuedBytes -= queued
	lease.limiter.mutex.Unlock()
}

func decrement[K comparable](values map[K]int, key K) {
	if values[key] <= 1 {
		delete(values, key)
		return
	}
	values[key]--
}
