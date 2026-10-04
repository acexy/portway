package link

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/control"
)

func TestContextStreamCancellationDoesNotWaitForControlWrite(t *testing.T) {
	broker := NewBroker(context.Background())
	defer broker.Close()
	connection, peer := net.Pipe()
	defer connection.Close()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelled := make(chan struct{})
	admitted := make(chan error, 1)
	go func() {
		admitted <- broker.ServeStreamContext(ctx, Target{
			ClientID: "client", SessionID: "session", BindingID: "binding",
			BindingName: "udp", TrafficType: TrafficTypeUDP, Writer: control.NewWriter(connection),
		}, func(string) { close(cancelled) }, nil)
	}()
	select {
	case err := <-admitted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("association admission waited for control I/O")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("pending cancellation waited for control I/O")
	}
}
