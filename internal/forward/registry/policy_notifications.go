package registry

import (
	"context"
	"sync"
	"time"

	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
)

const policyNotificationTimeout = 5 * time.Second
const maxPolicyNotificationSessions = 256

type policyNotice struct {
	message protocol.MessageType
	payload any
}

// PolicyNotifications owns immutable notices for one published policy generation.
// Deliver must finish before the next generation is applied. Each session has
// one sender, so revoke precedes activation and slow sessions cannot block peers.
type PolicyNotifications struct {
	sessions map[*control.Writer][]policyNotice
}

func (notifications *PolicyNotifications) add(writer *control.Writer, message protocol.MessageType, payload any) {
	notifications.sessions[writer] = append(notifications.sessions[writer], policyNotice{message, payload})
}

// Deliver joins all senders within one shared deadline. Cancellation and failed
// delivery close the control stream rather than leaving a stale client runtime.
func (notifications *PolicyNotifications) Deliver(ctx context.Context) {
	if notifications == nil {
		return
	}
	deadline := time.Now().Add(policyNotificationTimeout)
	if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	var senders sync.WaitGroup
	started := 0
	for writer, notices := range notifications.sessions {
		if writer == nil {
			continue
		}
		if started == maxPolicyNotificationSessions || ctx.Err() != nil {
			_ = writer.Close()
			continue
		}
		started++
		senders.Go(func() {
			stop := context.AfterFunc(ctx, func() { _ = writer.Close() })
			defer stop()
			for _, notice := range notices {
				if ctx.Err() != nil {
					_ = writer.Close()
					return
				}
				if err := writer.WriteUntil(deadline, notice.message, notice.payload); err != nil {
					_ = writer.Close()
					return
				}
			}
		})
	}
	senders.Wait()
}
