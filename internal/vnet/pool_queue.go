package vnet

import (
	"errors"
	"net"
	"sync/atomic"
	"time"
)

// Each pool reserves at most 64 queued packets, divided across stable channels.
// In-flight packets add at most ChannelCount * MTU bytes to this bound.
const poolQueuedPackets = 64

var ErrPacketQueueFull = errors.New("VNet packet queue full")

type packetQueueCounters struct {
	queued      atomic.Int64
	rejected    atomic.Uint64
	expired     atomic.Uint64
	revoked     atomic.Uint64
	writeFailed atomic.Uint64
}

// PacketQueueStatistics aggregates bounded outbound queues across pool generations.
type PacketQueueStatistics struct {
	Queued                                  int64
	Rejected, Expired, Revoked, WriteFailed uint64
}

func (broker *PoolBroker) QueueStatistics() PacketQueueStatistics {
	counters := &broker.queueCounters
	return PacketQueueStatistics{counters.queued.Load(), counters.rejected.Load(), counters.expired.Load(), counters.revoked.Load(), counters.writeFailed.Load()}
}

type queuedPacket struct {
	payload    []byte
	deadline   time.Time
	authorized func() bool
}

func (pool *Pool) startWriters() {
	pool.queues = make([]chan queuedPacket, len(pool.channels))
	for index := range pool.queues {
		queue := make(chan queuedPacket, poolQueuedPackets/len(pool.channels))
		pool.queues[index] = queue
		pool.writersDone.Go(func() {
			defer func() {
				for {
					select {
					case <-queue:
						pool.queueCounters.queued.Add(-1)
					default:
						return
					}
				}
			}()
			for {
				select {
				case <-pool.done:
					return
				case packet := <-queue:
					pool.queueCounters.queued.Add(-1)
					select {
					case <-pool.done:
						return
					default:
					}
					if !time.Now().Before(packet.deadline) {
						pool.queueCounters.expired.Add(1)
						continue
					}
					if packet.authorized != nil && !packet.authorized() {
						pool.queueCounters.revoked.Add(1)
						continue
					}
					if err := pool.writers[index].SendUntil(packet.payload, packet.deadline); err != nil {
						pool.queueCounters.writeFailed.Add(1)
						_ = pool.stop()
						return
					}
				}
			}
		})
	}
}

// Enqueue isolates shared ingress from slow destinations. It never waits for
// network I/O. A full queue drops this packet without disrupting other flows.
// authorized rechecks the captured policy/session generation before delivery.
func (pool *Pool) Enqueue(packet []byte, index uint8, authorized func() bool) error {
	pool.queueMutex.Lock()
	defer pool.queueMutex.Unlock()
	select {
	case <-pool.done:
		return net.ErrClosed
	default:
	}
	if int(index) >= len(pool.queues) || len(packet) > int(pool.spec.MTU) {
		return ErrInvalidPacket
	}
	queue := pool.queues[index]
	if len(queue) == cap(queue) {
		pool.queueCounters.rejected.Add(1)
		return ErrPacketQueueFull
	}
	pool.queueCounters.queued.Add(1)
	queue <- queuedPacket{payload: append([]byte(nil), packet...), deadline: time.Now().Add(pool.spec.WriteTimeout), authorized: authorized}
	return nil
}
