package vnet

import (
	"net/netip"
	"time"
)

const (
	maximumPairFlows  = 1024
	newFlowBurst      = 256
	newFlowsPerSecond = 128
	tcpFlowIdle       = 5 * time.Minute
	udpFlowIdle       = time.Minute
)

type nodePair [2][4]byte

type pairAdmission struct {
	count   int
	tokens  float64
	updated time.Time
}

// flowAdmission is protected by its owning router or endpoint lock.
// Idle buckets remain briefly to prevent quota release from resetting rate limits.
type flowAdmission struct {
	pairs       map[nodePair]pairAdmission
	nextCleanup time.Time
}

func makeNodePair(first, second netip.Addr) nodePair {
	if second.Less(first) {
		first, second = second, first
	}
	return nodePair{first.As4(), second.As4()}
}

func (admission *flowAdmission) admit(flow Flow, now time.Time, maximumBuckets int) error {
	if admission.pairs == nil {
		admission.pairs = make(map[nodePair]pairAdmission)
	}
	if !now.Before(admission.nextCleanup) {
		for key, state := range admission.pairs {
			if state.count == 0 && now.Sub(state.updated) >= time.Duration(newFlowBurst/newFlowsPerSecond)*time.Second {
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
		state = pairAdmission{tokens: newFlowBurst, updated: now}
	}
	if state.count >= maximumPairFlows {
		return ErrFlowCapacity
	}
	if now.After(state.updated) {
		state.tokens = min(newFlowBurst, state.tokens+now.Sub(state.updated).Seconds()*newFlowsPerSecond)
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

func (admission *flowAdmission) release(first, second netip.Addr) {
	key := makeNodePair(first, second)
	state, exists := admission.pairs[key]
	if exists && state.count > 0 {
		state.count--
		admission.pairs[key] = state
	}
}
