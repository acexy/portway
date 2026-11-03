package udp

import "sync/atomic"

// trafficCounters are fixed-cardinality interval counters owned by one Endpoint.
// Mirror traffic counts successful member-link transfers, not unique visitors.
type trafficCounters struct {
	created           atomic.Uint64
	expired           atomic.Uint64
	rejected          atomic.Uint64
	queueDropped      atomic.Uint64
	uplinkDatagrams   atomic.Uint64
	uplinkBytes       atomic.Uint64
	downlinkDatagrams atomic.Uint64
	downlinkBytes     atomic.Uint64
	writeTimeouts     atomic.Uint64
}

func (counters *trafficCounters) drain() (map[string]any, bool) {
	values := map[string]any{
		"created_associations":    counters.created.Swap(0),
		"expired_associations":    counters.expired.Swap(0),
		"rejected_associations":   counters.rejected.Swap(0),
		"queue_dropped_datagrams": counters.queueDropped.Swap(0),
		"uplink_datagrams":        counters.uplinkDatagrams.Swap(0),
		"uplink_bytes":            counters.uplinkBytes.Swap(0),
		"downlink_datagrams":      counters.downlinkDatagrams.Swap(0),
		"downlink_bytes":          counters.downlinkBytes.Swap(0),
		"write_timeouts":          counters.writeTimeouts.Swap(0),
	}
	active := false
	for _, value := range values {
		active = active || value.(uint64) != 0
	}
	return values, active
}
