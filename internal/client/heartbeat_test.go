package client

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
)

func heartbeatEnvelope(sequence uint64) protocol.Envelope {
	payload, _ := json.Marshal(protocol.Heartbeat{Sequence: sequence})
	return protocol.Envelope{Type: protocol.MessagePong, Payload: payload}
}

func TestHeartbeatStableRequiresContinuousValidPongs(t *testing.T) {
	start := time.Unix(1000, 0)
	state := newHeartbeatState(start)
	for elapsed := heartbeatInterval; elapsed <= stableSessionPeriod; elapsed += heartbeatInterval {
		sequence, err := state.nextSequence()
		if err != nil {
			t.Fatal(err)
		}
		if err := state.accept(heartbeatEnvelope(sequence), start.Add(elapsed)); err != nil {
			t.Fatal(err)
		}
		if state.stable() != (elapsed >= stableSessionPeriod) {
			t.Fatalf("unexpected stability at %s", elapsed)
		}
	}
	if !state.expired(start.Add(stableSessionPeriod + heartbeatTimeout)) {
		t.Fatal("missing heartbeat expiry")
	}
	if !state.stable() {
		t.Fatal("final disconnection erased established stability")
	}
}

func TestHeartbeatRejectsInvalidAndLateAcknowledgements(t *testing.T) {
	for _, test := range []struct {
		name     string
		sequence uint64
		elapsed  time.Duration
	}{
		{"zero", 0, time.Second}, {"future", 2, time.Second}, {"deadline", 1, heartbeatTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			start := time.Unix(1000, 0)
			state := newHeartbeatState(start)
			state.nextSequence()
			if err := state.accept(heartbeatEnvelope(test.sequence), start.Add(test.elapsed)); err == nil {
				t.Fatal("accepted invalid acknowledgement")
			}
			if !state.expired(start.Add(heartbeatTimeout)) {
				t.Fatal("invalid pong extended liveness")
			}
		})
	}
	start := time.Unix(1000, 0)
	state := newHeartbeatState(start)
	state.nextSequence()
	if err := state.accept(heartbeatEnvelope(1), start.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := state.accept(heartbeatEnvelope(1), start.Add(2*time.Second)); err == nil {
		t.Fatal("accepted duplicate acknowledgement")
	}
}

type heartbeatWriteStream struct {
	net.Conn
	started chan struct{}
}

func (stream heartbeatWriteStream) Write(data []byte) (int, error) {
	select {
	case stream.started <- struct{}{}:
	default:
	}
	return stream.Conn.Write(data)
}

func TestHeartbeatCancellationInterruptsBlockedWrite(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	started := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- writeHeartbeat(ctx, control.NewWriter(heartbeatWriteStream{local, started}), 1) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("write did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled heartbeat write leaked")
	}
}

func TestReconnectBackoffSurvivesFlappingSessions(t *testing.T) {
	backoff := reconnectBackoff{delay: maximumRegistrationReconnectDelay, attempt: 20}
	backoff.sessionEstablished(false)
	if backoff.delay != initialRecoveryReconnectDelay || backoff.attempt != 0 {
		t.Fatal("first session did not enable fast recovery")
	}
	backoff.delay, backoff.attempt = maximumRecoveryReconnectDelay, 10
	backoff.sessionEstablished(false)
	if backoff.delay != maximumRecoveryReconnectDelay || backoff.attempt != 10 {
		t.Fatal("short session reset backoff")
	}
	backoff.sessionEstablished(true)
	if backoff.delay != initialRecoveryReconnectDelay || backoff.attempt != 0 {
		t.Fatal("stable session did not reset backoff")
	}
}

func TestControlReaderRecordsPongBeforeBusinessDispatch(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := newHeartbeatState(time.Now())
	state.nextSequence()
	messages := make(chan protocol.Envelope, 1)
	readErrors := make(chan error, 1)
	done := make(chan struct{})
	go func() { defer close(done); readControlMessages(ctx, local, messages, readErrors, state) }()
	if err := protocol.WriteControl(peer, protocol.MessagePong, protocol.Heartbeat{Sequence: 1}); err != nil {
		t.Fatal(err)
	}
	// The following frame is an explicit barrier: processing it follows Pong validation.
	if err := protocol.WriteControl(peer, protocol.MessageCloseAck, protocol.CloseAck{}); err != nil {
		t.Fatal(err)
	}
	select {
	case envelope := <-messages:
		if envelope.Type != protocol.MessageCloseAck {
			t.Fatalf("pong entered business dispatch: %s", envelope.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("reader did not dispatch barrier")
	}
	state.mutex.Lock()
	acknowledged := state.acknowledged
	state.mutex.Unlock()
	if acknowledged != 1 {
		t.Fatal("Pong was not recorded before dispatch")
	}
	cancel()
	local.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reader leaked")
	}
}
