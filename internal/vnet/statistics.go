package vnet

// FlowStatistics is a low-cardinality snapshot. Rejections are cumulative.
type FlowStatistics struct {
	Active           int
	CapacityRejected uint64
	RateRejected     uint64
	PolicyRejected   uint64
}

// Statistics returns router occupancy and cumulative rejection counts.
func (router *Router) Statistics() FlowStatistics {
	router.mutex.Lock()
	defer router.mutex.Unlock()
	return FlowStatistics{Active: len(router.flows), CapacityRejected: router.capacityRejected, RateRejected: router.rateRejected, PolicyRejected: router.policyRejected}
}

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

// UserspaceStatistics reports bounded ownership and actual proxy resources.
type UserspaceStatistics struct {
	Flows           int
	TCPConnections  int
	UDPAssociations int
}

// Statistics distinguishes authorization records from actual proxy resources.
func (runtime *UserspaceTCP) Statistics() UserspaceStatistics {
	runtime.mutex.Lock()
	defer runtime.mutex.Unlock()
	return UserspaceStatistics{len(runtime.flows) + len(runtime.hostFlows), len(runtime.connections), len(runtime.associations)}
}
