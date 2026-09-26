package link

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
)

type testReservation struct {
	active  atomic.Int32
	closed  atomic.Int32
	cleaned *atomic.Bool
	t       *testing.T
}

func (reservation *testReservation) Activate() { reservation.active.Add(1) }
func (reservation *testReservation) Close() {
	if reservation.cleaned != nil && !reservation.cleaned.Load() {
		reservation.t.Error("capacity returned before target cleanup")
	}
	reservation.closed.Add(1)
}

func TestForwardPreparedTargetCleanup(t *testing.T) {
	for _, stage := range []string{"prepare", "response", "deadline", "handler"} {
		t.Run(stage, func(t *testing.T) {
			broker := NewBroker(context.Background())
			defer broker.Close()
			var cleaned atomic.Bool
			reservation := &testReservation{cleaned: &cleaned, t: t}
			target := Target{ClientID: "client", SessionID: "session", BindingID: "binding",
				TrafficType: TrafficTypeTCP, Direction: protocol.LinkDirectionForward, Reservation: reservation}
			calls := 0
			offer, err := broker.OfferStream(target, func(context.Context) (StreamHandler, func(), error) {
				cleanup := func() { cleaned.Store(true) }
				if stage == "prepare" {
					return nil, cleanup, io.ErrClosedPipe
				}
				return func(context.Context, string, net.Conn) error { calls++; return nil }, cleanup, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			connection := &deliveryFailureConnection{}
			if stage == "response" {
				connection.writeError = io.ErrClosedPipe
			} else if stage == "deadline" {
				connection.deadlineError = io.ErrClosedPipe
			}
			err = broker.Bind(context.Background(), connection, protocol.BindLink{
				ClientID: target.ClientID, SessionID: target.SessionID, BindingID: target.BindingID,
				ProxyType: protocol.ProxyTypeTCP, Direction: protocol.LinkDirectionForward,
				LinkID: offer.LinkID, Ticket: offer.Ticket,
			}, authentication.Context{})
			if (err == nil) != (stage == "handler") {
				t.Fatalf("unexpected bind error: %v", err)
			}
			if !cleaned.Load() || reservation.closed.Load() != 1 || !connection.closed.Load() {
				t.Fatal("prepared target, capacity or stream was not released")
			}
			if stage == "handler" {
				if calls != 1 || reservation.active.Load() != 1 {
					t.Fatal("successful stream was not activated")
				}
			} else if calls != 0 || reservation.active.Load() != 0 {
				t.Fatal("failed stream was activated")
			}
		})
	}
}

func TestForwardCancellationChecksOwnership(t *testing.T) {
	for _, active := range []bool{false, true} {
		for _, direction := range []protocol.LinkDirection{protocol.LinkDirectionForward, protocol.LinkDirectionProxy} {
			broker := NewBroker(context.Background())
			target := Target{ClientID: "owner", SessionID: "session", Direction: direction}
			connection := &deliveryFailureConnection{}
			cancelled := false
			linkID := "link"
			if active {
				broker.active[linkID] = &brokerActiveLink{target: target, connection: newManagedLinkConnection(connection)}
				broker.incrementActiveLocked(target)
			} else {
				offer, err := broker.createPending(target, func(string) { cancelled = true }, nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				linkID = offer.LinkID
			}
			broker.CancelForwardLink("other", "session", linkID)
			broker.CancelForwardLink("owner", "old-session", linkID)
			if connection.closed.Load() || cancelled {
				t.Fatal("foreign caller cancelled a link")
			}
			broker.CancelForwardLink("owner", "session", linkID)
			if (connection.closed.Load() || cancelled) != (direction == protocol.LinkDirectionForward) {
				t.Fatal("cancellation did not respect direction")
			}
			broker.Close()
		}
	}
}

func TestForwardCancellationInterruptsPreparation(t *testing.T) {
	broker := NewBroker(context.Background())
	defer broker.Close()
	started := make(chan struct{})
	target := Target{ClientID: "client", SessionID: "session", Direction: protocol.LinkDirectionForward}
	offer, err := broker.OfferStream(target, func(ctx context.Context) (StreamHandler, func(), error) {
		close(started)
		<-ctx.Done()
		return nil, nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- broker.Bind(context.Background(), &deliveryFailureConnection{}, protocol.BindLink{
			ClientID: target.ClientID, SessionID: target.SessionID, Direction: protocol.LinkDirectionForward,
			LinkID: offer.LinkID, Ticket: offer.Ticket,
		}, authentication.Context{})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("preparation did not start")
	}
	broker.CancelForwardLink("client", "session", offer.LinkID)
	select {
	case err := <-done:
		if err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("preparation returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt target preparation")
	}
	if stats := broker.SnapshotStats(); stats.Active != 0 || stats.Pending != 0 {
		t.Fatalf("cancelled preparation retained links: %+v", stats)
	}
}
