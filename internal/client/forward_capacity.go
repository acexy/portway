package client

import (
	"sync"

	"github.com/acexy/portway/internal/limits"
)

const (
	maxForwardPending            = 128
	maxForwardPendingPerName     = 64
	maxForwardConnections        = limits.HardMaxActiveLinksPerClient
	maxForwardConnectionsPerName = 256
)

type forwardCounts struct {
	pending int
	total   int
}

type forwardCapacity struct {
	mutex sync.Mutex
	all   forwardCounts
	names map[string]forwardCounts
}

type forwardLease struct {
	capacity *forwardCapacity
	name     string
	pending  bool
	closed   bool
}

func (capacity *forwardCapacity) acquire(name string) *forwardLease {
	capacity.mutex.Lock()
	defer capacity.mutex.Unlock()
	counts := capacity.names[name]
	if capacity.all.pending >= maxForwardPending || counts.pending >= maxForwardPendingPerName ||
		capacity.all.total >= maxForwardConnections || counts.total >= maxForwardConnectionsPerName {
		return nil
	}
	if capacity.names == nil {
		capacity.names = make(map[string]forwardCounts)
	}
	capacity.all.pending++
	capacity.all.total++
	counts.pending++
	counts.total++
	capacity.names[name] = counts
	return &forwardLease{capacity: capacity, name: name, pending: true}
}

func (lease *forwardLease) activate() {
	lease.capacity.mutex.Lock()
	defer lease.capacity.mutex.Unlock()
	if lease.closed || !lease.pending {
		return
	}
	lease.pending = false
	counts := lease.capacity.names[lease.name]
	counts.pending--
	lease.capacity.all.pending--
	lease.capacity.names[lease.name] = counts
}

func (lease *forwardLease) close() {
	lease.capacity.mutex.Lock()
	defer lease.capacity.mutex.Unlock()
	if lease.closed {
		return
	}
	lease.closed = true
	counts := lease.capacity.names[lease.name]
	counts.total--
	lease.capacity.all.total--
	if lease.pending {
		counts.pending--
		lease.capacity.all.pending--
	}
	if counts.total == 0 {
		delete(lease.capacity.names, lease.name)
	} else {
		lease.capacity.names[lease.name] = counts
	}
}
