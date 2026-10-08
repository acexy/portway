package client

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

// heartbeatState shares only liveness metadata between the sole reader and
// the heartbeat sender. Business-message processing never extends liveness.
type heartbeatState struct {
	mutex        sync.Mutex
	startedAt    time.Time
	lastPongAt   time.Time
	sent         uint64
	acknowledged uint64
	healthy      bool
}

func newHeartbeatState(now time.Time) *heartbeatState {
	return &heartbeatState{startedAt: now, lastPongAt: now}
}

func (heartbeat *heartbeatState) nextSequence() (uint64, error) {
	heartbeat.mutex.Lock()
	defer heartbeat.mutex.Unlock()
	if heartbeat.sent == math.MaxUint64 {
		return 0, errors.New("heartbeat sequence exhausted")
	}
	heartbeat.sent++
	return heartbeat.sent, nil
}

func (heartbeat *heartbeatState) accept(envelope protocol.Envelope, now time.Time) error {
	var pong protocol.Heartbeat
	if err := protocol.DecodePayload(envelope, &pong); err != nil {
		return classifyControlProtocolError(err)
	}
	heartbeat.mutex.Lock()
	defer heartbeat.mutex.Unlock()
	if pong.Sequence <= heartbeat.acknowledged || pong.Sequence > heartbeat.sent {
		return fmt.Errorf("%w: unexpected heartbeat sequence %d", transport.ErrProtocol, pong.Sequence)
	}
	if now.Sub(heartbeat.lastPongAt) >= heartbeatTimeout {
		return heartbeatTimeoutError()
	}
	heartbeat.acknowledged = pong.Sequence
	heartbeat.lastPongAt = now
	if now.Sub(heartbeat.startedAt) >= stableSessionPeriod {
		heartbeat.healthy = true
	}
	return nil
}

func (heartbeat *heartbeatState) expired(now time.Time) bool {
	heartbeat.mutex.Lock()
	defer heartbeat.mutex.Unlock()
	return now.Sub(heartbeat.lastPongAt) >= heartbeatTimeout
}

func (heartbeat *heartbeatState) stable() bool {
	heartbeat.mutex.Lock()
	defer heartbeat.mutex.Unlock()
	return heartbeat.healthy
}

func heartbeatTimeoutError() error {
	return fmt.Errorf("server heartbeat timed out after %s", heartbeatTimeout)
}

func runHeartbeat(ctx context.Context, writer *control.Writer, heartbeat *heartbeatState, logger *logging.Logger) error {
	ping := time.NewTicker(heartbeatInterval)
	defer ping.Stop()
	watchdog := time.NewTicker(heartbeatCheckInterval)
	defer watchdog.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-watchdog.C:
			if heartbeat.expired(time.Now()) {
				return heartbeatTimeoutError()
			}
		case <-ping.C:
			if heartbeat.expired(time.Now()) {
				return heartbeatTimeoutError()
			}
			sequence, err := heartbeat.nextSequence()
			if err != nil {
				return err
			}
			if err := writeHeartbeat(ctx, writer, sequence); err != nil {
				return err
			}
			logger.TraceWithField("heartbeat ping sent", "sequence", sequence)
		}
	}
}

func writeHeartbeat(ctx context.Context, writer *control.Writer, sequence uint64) error {
	if ctx.Err() != nil {
		return nil
	}
	// Complete an admitted frame before graceful close; cancellation must not
	// close the shared control stream. Writer bounds stalled network I/O.
	return writer.Write(protocol.MessagePing, protocol.Heartbeat{Sequence: sequence})
}
