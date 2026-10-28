package flowcontrol

// FlowStatistics is a low-cardinality snapshot. Rejections are cumulative.
type FlowStatistics struct {
	Active           int
	CapacityRejected uint64
	RateRejected     uint64
	PolicyRejected   uint64
}
