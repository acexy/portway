package client

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
)

// blackholeConnection acknowledges writes without delivering bytes, preserving
// the open stream and its reverse direction instead of simulating an EOF.
type blackholeConnection struct {
	net.Conn
	drop atomic.Bool
}

func (connection *blackholeConnection) Write(data []byte) (int, error) {
	if connection.drop.Load() {
		return len(data), nil
	}
	return connection.Conn.Write(data)
}

func TestHeartbeatOneWayBlackhole(t *testing.T) {
	for _, direction := range []string{"client_to_server", "server_to_client"} {
		t.Run(direction, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, remote := net.Pipe()
				client := &blackholeConnection{Conn: local}
				server := &blackholeConnection{Conn: remote}
				defer client.Close()
				defer server.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				state := newHeartbeatState(time.Now())
				messages := make(chan protocol.Envelope, 1)
				readErrors := make(chan error, 1)
				go readControlMessages(ctx, client, messages, readErrors, state)
				var received atomic.Uint64
				go func() {
					for {
						envelope, err := protocol.ReadControl(server)
						if err != nil {
							return
						}
						var ping protocol.Heartbeat
						if err := protocol.DecodePayload(envelope, &ping); err != nil {
							t.Error(err)
							return
						}
						received.Add(1)
						if err := protocol.WriteControl(server, protocol.MessagePong, ping); err != nil {
							return
						}
					}
				}()
				done := make(chan error, 1)
				go func() { done <- runHeartbeat(ctx, control.NewWriter(client), state, logging.New("test")) }()
				time.Sleep(heartbeatInterval)
				synctest.Wait()
				if state.acknowledged != 1 {
					t.Fatal("healthy connection did not exchange a heartbeat")
				}
				if direction == "client_to_server" {
					client.drop.Store(true)
				} else {
					server.drop.Store(true)
				}
				time.Sleep(heartbeatTimeout - time.Nanosecond)
				synctest.Wait()
				select {
				case err := <-done:
					t.Fatalf("heartbeat stopped before timeout: %v", err)
				default:
				}
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				select {
				case err := <-done:
					if err == nil || err.Error() != heartbeatTimeoutError().Error() {
						t.Fatalf("expected heartbeat timeout, got %v", err)
					}
				default:
					t.Fatal("silent one-way failure did not expire")
				}
				if state.acknowledged != 1 {
					t.Fatal("blackholed heartbeats refreshed liveness")
				}
				if direction == "client_to_server" && received.Load() != 1 {
					t.Fatal("blackholed Ping reached server")
				}
				if direction == "server_to_client" && received.Load() <= 1 {
					t.Fatal("reverse-direction failure also blocked Ping")
				}
				select {
				case err := <-readErrors:
					t.Fatalf("blackhole unexpectedly closed the stream: %v", err)
				default:
				}
				// Cancellation and stream closure must release every blocked reader.
				cancel()
				client.Close()
				server.Close()
				synctest.Wait()
			})
		})
	}
}

func TestHeartbeatBusinessQueueCongestion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, peer := net.Pipe()
		defer local.Close()
		defer peer.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		state := newHeartbeatState(time.Now())
		messages := make(chan protocol.Envelope, 1)
		readErrors := make(chan error, 1)
		go readControlMessages(ctx, local, messages, readErrors, state)
		// Two business frames fill the queue and block dispatch of the second.
		for range 2 {
			if err := protocol.WriteControl(peer, protocol.MessageCloseAck, protocol.CloseAck{}); err != nil {
				t.Fatal(err)
			}
		}
		go func() {
			envelope, err := protocol.ReadControl(peer)
			if err != nil {
				return
			}
			var ping protocol.Heartbeat
			if err := protocol.DecodePayload(envelope, &ping); err != nil {
				t.Error(err)
				return
			}
			_ = protocol.WriteControl(peer, protocol.MessagePong, ping)
		}()
		done := make(chan error, 1)
		go func() { done <- runHeartbeat(ctx, control.NewWriter(local), state, logging.New("test")) }()
		// The blocked Pong prevents the peer from reading further Pings; the
		// bounded writer must terminate the heartbeat task and close the stream.
		time.Sleep(heartbeatTimeout)
		synctest.Wait()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("congestion did not fail the control channel")
			}
		default:
			t.Fatal("congested heartbeat task did not terminate")
		}
		if state.acknowledged != 0 {
			t.Fatal("Pong behind blocked business dispatch refreshed liveness")
		}
		cancel()
		local.Close()
		synctest.Wait()
	})
}

func TestRepeatedShortSessionsRequireHealthyPongsToResetBackoff(t *testing.T) {
	backoff := reconnectBackoff{delay: initialRegistrationReconnectDelay}
	backoff.sessionEstablished(false)
	for attempt := uint64(1); attempt <= 12; attempt++ {
		state := newHeartbeatState(time.Unix(1000, 0))
		for elapsed := heartbeatInterval; elapsed < stableSessionPeriod; elapsed += heartbeatInterval {
			sequence, err := state.nextSequence()
			if err != nil {
				t.Fatal(err)
			}
			if err := state.accept(heartbeatEnvelope(sequence), state.startedAt.Add(elapsed)); err != nil {
				t.Fatal(err)
			}
		}
		backoff.attempt++
		backoff.delay = nextReconnectDelay(backoff.delay, reconnectPhaseRecovery)
		expectedDelay := backoff.delay
		backoff.sessionEstablished(state.stable())
		if backoff.attempt != attempt || backoff.delay != expectedDelay {
			t.Fatalf("short session %d reset retry history: %+v", attempt, backoff)
		}
	}
	if backoff.delay != maximumRecoveryReconnectDelay {
		t.Fatal("repeated failures did not reach recovery backoff cap")
	}
	state := newHeartbeatState(time.Unix(2000, 0))
	for elapsed := heartbeatInterval; elapsed <= stableSessionPeriod; elapsed += heartbeatInterval {
		sequence, err := state.nextSequence()
		if err != nil {
			t.Fatal(err)
		}
		if err := state.accept(heartbeatEnvelope(sequence), state.startedAt.Add(elapsed)); err != nil {
			t.Fatal(err)
		}
	}
	backoff.sessionEstablished(state.stable())
	if backoff.attempt != 0 || backoff.delay != initialRecoveryReconnectDelay {
		t.Fatalf("healthy session did not restore fast recovery: %+v", backoff)
	}
}
