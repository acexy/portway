package userspace

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
