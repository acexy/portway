package flowcontrol

import (
	"errors"
	"net/netip"
	"time"

	packetdata "github.com/acexy/portway/internal/vnet/packet"
)

const (
	MaximumPairFlows  = 1024
	NewFlowBurst      = 256
	newFlowsPerSecond = 128
	TCPFlowIdle       = 5 * time.Minute
	UDPFlowIdle       = time.Minute
)

var (
	ErrFlowCapacity = errors.New("VNet flow capacity reached")
	ErrFlowRate     = errors.New("VNet new flow rate reached")
)

type nodePair [2][4]byte

type pairAdmission struct {
	count   int
	tokens  float64
	updated time.Time
}

// Admission is protected by its owning router or endpoint lock.
// Idle buckets remain briefly to prevent quota release from resetting rate limits.
type Admission struct {
	pairs       map[nodePair]pairAdmission
	nextCleanup time.Time
}

func makeNodePair(first, second netip.Addr) nodePair {
	if second.Less(first) {
		first, second = second, first
	}
	return nodePair{first.As4(), second.As4()}
}

// Admit reserves one flow within the pair capacity and new-flow rate limits.
func (admission *Admission) Admit(flow packetdata.Flow, now time.Time, maximumBuckets int) error {
	if admission.pairs == nil {
		admission.pairs = make(map[nodePair]pairAdmission)
	}
	if !now.Before(admission.nextCleanup) {
		for key, state := range admission.pairs {
			if state.count == 0 && now.Sub(state.updated) >= time.Duration(NewFlowBurst/newFlowsPerSecond)*time.Second {
				delete(admission.pairs, key)
			}
		}
		admission.nextCleanup = now.Add(time.Second)
	}
	key := makeNodePair(flow.SourceIP, flow.DestinationIP)
	state, exists := admission.pairs[key]
	if !exists {
		if len(admission.pairs) >= maximumBuckets {
			return ErrFlowCapacity
		}
		state = pairAdmission{tokens: NewFlowBurst, updated: now}
	}
	if state.count >= MaximumPairFlows {
		return ErrFlowCapacity
	}
	if now.After(state.updated) {
		state.tokens = min(NewFlowBurst, state.tokens+now.Sub(state.updated).Seconds()*newFlowsPerSecond)
		state.updated = now
	}
	if state.tokens < 1 {
		admission.pairs[key] = state
		return ErrFlowRate
	}
	state.tokens--
	state.count++
	admission.pairs[key] = state
	return nil
}

// Release returns capacity without resetting the pair's rate budget.
func (admission *Admission) Release(first, second netip.Addr) {
	key := makeNodePair(first, second)
	state, exists := admission.pairs[key]
	if exists && state.count > 0 {
		state.count--
		admission.pairs[key] = state
	}
}

// Count returns the active quota for a node pair under the caller's lock.
func (admission *Admission) Count(first, second netip.Addr) int {
	return admission.pairs[makeNodePair(first, second)].count
}
