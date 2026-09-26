package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	forwardtcp "github.com/acexy/portway/internal/forward/tcp"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

func TestForwardCapacityBoundsPendingAndActive(t *testing.T) {
	capacity := &forwardCapacity{}
	leases := make([]*forwardLease, 0, maxForwardConnections)
	for name := range 2 {
		for range maxForwardPendingPerName {
			lease := capacity.acquire(fmt.Sprint(name))
			if lease == nil {
				t.Fatal("capacity rejected an available pending slot")
			}
			leases = append(leases, lease)
		}
		if capacity.acquire(fmt.Sprint(name)) != nil {
			t.Fatal("per-forward pending limit was exceeded")
		}
	}
	if capacity.acquire("another") != nil {
		t.Fatal("global pending limit was exceeded")
	}
	for _, lease := range leases {
		lease.activate()
		lease.activate()
	}
	for name := range 2 {
		for range maxForwardConnectionsPerName - maxForwardPendingPerName {
			lease := capacity.acquire(fmt.Sprint(name))
			if lease == nil {
				t.Fatal("active transition retained pending capacity")
			}
			lease.activate()
			leases = append(leases, lease)
		}
		if capacity.acquire(fmt.Sprint(name)) != nil {
			t.Fatal("per-forward total limit was exceeded")
		}
	}
	if capacity.acquire("another") != nil {
		t.Fatal("global total limit was exceeded")
	}
	for _, lease := range leases {
		lease.close()
		lease.close()
		lease.activate()
	}
	if capacity.all != (forwardCounts{}) || len(capacity.names) != 0 {
		t.Fatal("capacity was not fully released")
	}
}

func TestForwardTCPAdmissionRejectsBeforeCreatingOffer(t *testing.T) {
	manager, err := newForwardManager(context.Background(), logging.New("test"), "client", "session", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &forwardRuntime{context: manager.context, cancel: func() {}, configuration: config.ForwardConfig{Name: "tcp"}}
	runtime.tcp, err = forwardtcp.Listen(manager.context, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	manager.runtimes["tcp"] = runtime
	defer manager.close()
	for range maxForwardPendingPerName {
		lease := manager.tcpCapacity.acquire("tcp")
		defer lease.close()
	}
	manager.serveRuntime(runtime)
	visitor, err := net.Dial("tcp", runtime.tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer visitor.Close()
	visitor.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := visitor.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("over-capacity visitor was not immediately closed: %v", err)
	}
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if len(manager.offers) != 0 {
		t.Fatal("over-capacity visitor created an offer")
	}
}

type forwardTestSession struct {
	transport.ClientSession
	open func(context.Context) (transport.Stream, error)
}

func (session forwardTestSession) OpenDataStream(ctx context.Context) (transport.Stream, error) {
	return session.open(ctx)
}

func TestForwardCancellationBetweenOfferAndBind(t *testing.T) {
	for _, kind := range []protocol.ForwardType{protocol.ForwardTypeTCP, protocol.ForwardTypeUDP} {
		t.Run(string(kind), func(t *testing.T) {
			manager, _ := newForwardManager(context.Background(), logging.New("test"), "client", "session",
				control.NewWriter(io.Discard), nil, nil)
			defer manager.close()
			runtime := &forwardRuntime{bindingID: "binding", configuration: config.ForwardConfig{Name: "forward", Type: kind}}
			request := &forwardOfferRequest{context: manager.context, runtime: runtime, ready: make(chan protocol.ForwardLinkOffer, 1)}
			manager.offers["request"] = request
			offer := protocol.ForwardLinkOffer{RequestID: "request", LinkID: "link", Ticket: "test-ticket",
				Name: "forward", Type: kind, BindingID: "binding", ExpiresAtUnixMS: time.Now().Add(time.Minute).UnixMilli()}
			manager.deliverOffer(offer)
			manager.cancelLink("link")
			if request.link == nil || request.link.context.Err() == nil {
				t.Fatal("cancel arriving before offer consumption was lost")
			}
			manager.releaseForwardLink(request.link)
		})
	}
}

func TestForwardCancellationInterruptsBind(t *testing.T) {
	for _, kind := range []protocol.ForwardType{protocol.ForwardTypeTCP, protocol.ForwardTypeUDP} {
		t.Run(string(kind), func(t *testing.T) {
			manager, _ := newForwardManager(context.Background(), logging.New("test"), "client", "session",
				control.NewWriter(io.Discard), nil, nil)
			defer manager.close()
			connection, peer := net.Pipe()
			defer peer.Close()
			manager.transport = forwardTestSession{open: func(context.Context) (transport.Stream, error) {
				return recoveryControlStream{Conn: connection}, nil
			}}
			ctx, cancel := context.WithCancel(manager.context)
			link := &forwardLink{context: ctx, cancel: cancel, offer: protocol.ForwardLinkOffer{
				LinkID: "link", Ticket: "test-ticket", Type: kind, BindingID: "binding",
				ExpiresAtUnixMS: time.Now().Add(time.Minute).UnixMilli(),
			}}
			manager.links["link"] = link
			done := make(chan struct{})
			go func() {
				defer close(done)
				manager.serveForwardStream(link, func(context.Context, transport.Stream) { t.Error("cancelled bind entered forwarding") })
			}()
			peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := protocol.ReadControl(peer); err != nil {
				t.Fatal(err)
			}
			manager.cancelLink("link")
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("bind cancellation waited for its five-second deadline")
			}
			if len(manager.links) != 0 {
				t.Fatal("cancelled bind retained registration")
			}
		})
	}
}

func TestForwardOfferExpiryBoundsDataStreamOpening(t *testing.T) {
	manager, _ := newForwardManager(context.Background(), logging.New("test"), "client", "session",
		control.NewWriter(io.Discard), nil, nil)
	defer manager.close()
	manager.transport = forwardTestSession{open: func(ctx context.Context) (transport.Stream, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithCancel(manager.context)
	link := &forwardLink{context: ctx, cancel: cancel, offer: protocol.ForwardLinkOffer{
		LinkID: "link", ExpiresAtUnixMS: time.Now().Add(20 * time.Millisecond).UnixMilli(),
	}}
	manager.links["link"] = link
	done := make(chan struct{})
	go func() { defer close(done); manager.serveForwardStream(link, nil) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expired offer retained a stream-opening task")
	}
}
