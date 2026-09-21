package server

import (
	"context"
	"sync"
	"time"

	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
)

const vnetPeerNoticeTimeout = 5 * time.Second
const vnetPeerNoticeCapacity = 128

type vnetPeerNotice struct {
	message  protocol.MessageType
	payload  any
	deadline time.Time
}

// Each session owns one sender. Queue admission never waits for network I/O.
// A lost security notice closes the session instead of retaining stale authority.
type vnetPeerNotifier struct {
	context context.Context
	cancel  context.CancelFunc
	writer  *control.Writer
	queue   chan vnetPeerNotice
	once    sync.Once
}

func (runtime *serverVNetRuntime) newPeerNotifier(writer *control.Writer) *vnetPeerNotifier {
	ctx, cancel := context.WithCancel(runtime.context)
	notifier := &vnetPeerNotifier{context: ctx, cancel: cancel, writer: writer, queue: make(chan vnetPeerNotice, vnetPeerNoticeCapacity)}
	runtime.waitGroup.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case notice := <-notifier.queue:
				if ctx.Err() != nil {
					return
				}
				if err := writer.WriteUntil(notice.deadline, notice.message, notice.payload); err != nil {
					notifier.abort()
					runtime.logger.WarnWithFields("VNet peer notification failed; closing control session", err, map[string]any{"event": "vnet_peer_notice_failed"})
					return
				}
			}
		}
	})
	return notifier
}

func (notifier *vnetPeerNotifier) enqueue(message protocol.MessageType, payload any) bool {
	if notifier == nil || notifier.context.Err() != nil {
		return false
	}
	select {
	case notifier.queue <- vnetPeerNotice{message, payload, time.Now().Add(vnetPeerNoticeTimeout)}:
		return true
	default:
		notifier.abort()
		return false
	}
}

func (notifier *vnetPeerNotifier) abort() {
	notifier.once.Do(func() { notifier.cancel(); _ = notifier.writer.Close() })
}

func (runtime *serverVNetRuntime) reportVNetStatistics() {
	runtime.mutex.RLock()
	enabled := runtime.configuration.Enabled
	pairs, active := len(runtime.peerPairs), 0
	for _, pair := range runtime.peerPairs {
		if pair.active {
			active++
		}
	}
	userspace := runtime.userspaceTCP
	runtime.mutex.RUnlock()
	if !enabled || runtime.router == nil {
		return
	}
	statistics := runtime.router.Statistics()
	fields := map[string]any{"event": "vnet_statistics", "flows": statistics.Active,
		"capacity_rejected": statistics.CapacityRejected, "rate_rejected": statistics.RateRejected, "policy_rejected": statistics.PolicyRejected,
		"peer_pairs": pairs, "direct_pairs": active}
	if userspace != nil {
		local := userspace.Statistics()
		fields["userspace_flows"], fields["tcp_connections"], fields["udp_associations"] = local.Flows, local.TCPConnections, local.UDPAssociations
	}
	runtime.logger.DebugWithFields("VNet resource statistics", fields)
}
