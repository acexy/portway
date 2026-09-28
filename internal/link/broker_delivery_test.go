package link

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
)

type deliveryFailureConnection struct {
	net.Conn
	writeError    error
	deadlineError error
	closed        atomic.Bool
}

func (connection *deliveryFailureConnection) Write(payload []byte) (int, error) {
	if connection.writeError != nil {
		return 0, connection.writeError
	}
	return len(payload), nil
}

func (connection *deliveryFailureConnection) SetDeadline(time.Time) error {
	return connection.deadlineError
}

func (connection *deliveryFailureConnection) Close() error {
	connection.closed.Store(true)
	return nil
}

func TestBindFailureNotifiesOwnerAfterPromotion(t *testing.T) {
	for _, stage := range []string{"response", "deadline"} {
		t.Run(stage, func(t *testing.T) {
			broker := NewBroker(context.Background())
			defer broker.Close()
			target := Target{
				ClientID: "client", SessionID: "session", BindingID: "binding",
				BindingName: "proxy", TrafficType: TrafficTypeTCP,
			}
			ready := make(chan linkOpenResult, 1)
			cancelled := 0
			offer, err := broker.createPending(target, func(string) { cancelled++ }, ready,
				func(context.Context, string, net.Conn) error {
					t.Fatal("failed stream was delivered to handler")
					return nil
				}, nil)
			if err != nil {
				t.Fatal(err)
			}
			connection := &deliveryFailureConnection{}
			if stage == "response" {
				connection.writeError = io.ErrClosedPipe
			} else {
				connection.deadlineError = io.ErrClosedPipe
			}
			err = broker.Bind(context.Background(), connection, protocol.BindLink{
				ClientID: target.ClientID, SessionID: target.SessionID,
				ProxyType: protocol.ProxyTypeTCP, BindingID: target.BindingID,
				LinkID: offer.LinkID, Ticket: offer.Ticket,
			}, authentication.Context{})
			if !errors.Is(err, io.ErrClosedPipe) || !connection.closed.Load() {
				t.Fatalf("bind error = %v, closed = %v", err, connection.closed.Load())
			}
			broker.CancelLink(offer.LinkID)
			broker.Close()
			if cancelled != 1 {
				t.Fatalf("owner notified %d times", cancelled)
			}
			select {
			case result := <-ready:
				if !errors.Is(result.err, io.ErrClosedPipe) || result.connection != nil {
					t.Fatalf("unexpected delivery: %+v", result)
				}
			default:
				t.Fatal("stream waiter was not notified")
			}
			if stats := broker.SnapshotStats(); stats.Pending != 0 || stats.Active != 0 {
				t.Fatalf("retained links: %+v", stats)
			}
			if len(broker.pendingClients)+len(broker.activeClients) != 0 {
				t.Fatal("capacity counters were retained")
			}
		})
	}
}

type blockedControlWriter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (writer *blockedControlWriter) Write([]byte) (int, error) {
	writer.once.Do(func() { close(writer.started) })
	<-writer.release
	return 0, io.ErrClosedPipe
}

func TestAsyncStreamSendRetainsCapacityUntilWriterExits(t *testing.T) {
	broker := NewBroker(context.Background())
	broker.sendSlots = make(chan struct{}, 1)
	writer := &blockedControlWriter{started: make(chan struct{}), release: make(chan struct{})}
	defer broker.Close()
	defer close(writer.release)
	target := Target{ClientID: "client", BindingName: "proxy", Writer: control.NewWriter(writer)}
	cancelled := make(chan struct{}, 1)
	linkID, err := broker.ServeStreamAsync(target, func(string) { cancelled <- struct{}{} }, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("control writer did not start")
	}
	// Releasing the Pending reservation must not admit another blocked sender.
	broker.ReportFailure(target.ClientID, "", protocol.LinkFailed{LinkID: linkID})
	if _, err := broker.ServeStreamAsync(target, nil, nil); !errors.Is(err, ErrCapacityReached) {
		t.Fatalf("send capacity was released prematurely: %v", err)
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("pending owner was not cancelled")
	}
}

func TestAsyncStreamWriteFailureClosesVisitor(t *testing.T) {
	broker := NewBroker(context.Background())
	defer broker.Close()
	connection, peer := net.Pipe()
	peer.Close()
	defer connection.Close()
	cancelled := make(chan struct{}, 1)
	_, err := broker.ServeStreamAsync(Target{Writer: control.NewWriter(connection)},
		func(string) { cancelled <- struct{}{} }, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("failed send retained the visitor")
	}
	broker.Close()
	if len(broker.sendSlots) != 0 || broker.SnapshotStats().Pending != 0 {
		t.Fatal("failed send retained capacity")
	}
}
