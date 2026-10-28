package peer

import (
	"github.com/acexy/portway/internal/vnet/internal/flowcontrol"
)

// FlowStatistics is the shared low-cardinality flow rejection snapshot.
type FlowStatistics = flowcontrol.FlowStatistics

// PeerStatistics includes both relay ownership and active direct flows.
type PeerStatistics struct {
	FlowStatistics
	ActivePeers int
	Fallbacks   uint64
}

// Statistics returns direct-path occupancy and cumulative resource rejections.
func (endpoint *PeerEndpoint) Statistics() PeerStatistics {
	endpoint.mutex.Lock()
	defer endpoint.mutex.Unlock()
	return PeerStatistics{FlowStatistics: FlowStatistics{Active: len(endpoint.flows), CapacityRejected: endpoint.capacityRejected, RateRejected: endpoint.rateRejected}, ActivePeers: len(endpoint.activeByIP), Fallbacks: endpoint.fallbacks}
}
