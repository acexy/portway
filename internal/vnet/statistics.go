package vnet

import (
	"github.com/acexy/portway/internal/vnet/internal/flowcontrol"
)

// FlowStatistics is the shared low-cardinality flow rejection snapshot.
type FlowStatistics = flowcontrol.FlowStatistics

// Statistics returns router occupancy and cumulative rejection counts.
func (router *Router) Statistics() FlowStatistics {
	router.mutex.Lock()
	defer router.mutex.Unlock()
	return FlowStatistics{Active: len(router.flows), CapacityRejected: router.capacityRejected, RateRejected: router.rateRejected, PolicyRejected: router.policyRejected}
}

// PoolStatistics counts registered pools and channels in published active pools.
type PoolStatistics struct {
	Pending        int
	Active         int
	ActiveChannels int
}

// Statistics takes a bounded snapshot without retaining pool connections.
func (broker *PoolBroker) Statistics() PoolStatistics {
	broker.mutex.Lock()
	defer broker.mutex.Unlock()
	statistics := PoolStatistics{Pending: len(broker.pending), Active: len(broker.active)}
	for _, pool := range broker.active {
		statistics.ActiveChannels += len(pool.channels)
	}
	return statistics
}
