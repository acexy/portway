package server

import (
	"github.com/acexy/portway/internal/vnet"
	"github.com/acexy/portway/internal/vnet/userspace"
)

// Each owner is sampled separately; no business lock is held during HTTP writes.
type operationsVNetStats struct {
	enabled     uint64
	deviceOpen  uint64
	preparing   uint64
	nodes       int
	sessions    int
	generation  uint64
	peerPairs   int
	directPairs int
	pools       vnet.PoolStatistics
	flows       vnet.FlowStatistics
	queues      vnet.PacketQueueStatistics
	userspace   userspace.UserspaceStatistics
}

func (runtime *serverVNetRuntime) operationsStats() operationsVNetStats {
	var stats operationsVNetStats
	if runtime == nil {
		return stats
	}
	runtime.mutex.RLock()
	if runtime.configuration.Enabled {
		stats.enabled = 1
	}
	if runtime.device != nil {
		stats.deviceOpen = 1
	}
	stats.nodes = len(runtime.configuration.Nodes)
	stats.sessions = len(runtime.sessions)
	stats.generation = runtime.configGeneration.Load()
	stats.peerPairs = len(runtime.peerPairs)
	for _, pair := range runtime.peerPairs {
		if pair.active {
			stats.directPairs++
		}
	}
	userspace := runtime.userspaceTCP
	runtime.mutex.RUnlock()
	if runtime.preparingDevice.Load() {
		stats.preparing = 1
	}
	if runtime.router != nil {
		stats.flows = runtime.router.Statistics()
	}
	if runtime.broker != nil {
		stats.pools = runtime.broker.Statistics()
		stats.queues = runtime.broker.QueueStatistics()
	}
	if userspace != nil {
		stats.userspace = userspace.Statistics()
	}
	return stats
}
