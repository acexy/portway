package vnet

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
)

func TestPoolPublicationWaitsForEveryAcknowledgement(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[failure], func(t *testing.T) {
			broker := NewPoolBroker()
			defer broker.Close()
			spec := PoolSpec{ClientID: "client", SessionID: "session", VirtualIP: "172.20.0.2",
				PoolGeneration: 1, ChannelCount: 2, MTU: 1150, WriteTimeout: time.Second}
			offers, err := broker.Prepare(spec, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			activated := make(chan *Pool, 1)
			finished := make(chan error, 2)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			for index, offer := range offers {
				server, peer := net.Pipe()
				defer peer.Close()
				go func() {
					finished <- broker.Bind(ctx, server, protocol.BindVNetChannel{
						ClientID: spec.ClientID, SessionID: spec.SessionID, VirtualIP: spec.VirtualIP,
						PoolGeneration: 1, ChannelCount: 2, ChannelIndex: uint8(index), Ticket: offer.Ticket,
					}, authentication.Context{}, func() error {
						entered <- struct{}{}
						select {
						case <-release:
						case <-ctx.Done():
							return ctx.Err()
						}
						if failure && index == 0 {
							return errors.New("acknowledgement failed")
						}
						return nil
					}, func(pool *Pool) { activated <- pool })
				}()
			}
			for range offers {
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("acknowledgement did not start")
				}
			}
			if _, active := broker.Active(spec.ClientID); active {
				t.Fatal("unacknowledged pool became visible")
			}
			close(release)
			if !failure {
				select {
				case <-activated:
				case <-time.After(time.Second):
					t.Fatal("ready pool did not activate")
				}
				cancel()
			}
			for range offers {
				select {
				case <-finished:
				case <-time.After(time.Second):
					t.Fatal("binding did not terminate")
				}
			}
			if _, active := broker.Active(spec.ClientID); active {
				t.Fatal("failed or cancelled pool retained")
			}
		})
	}
}

func TestDisabledRouterClearsAndRejectsFlows(t *testing.T) {
	configuration := testVNetConfiguration()
	router, err := NewRouter(configuration, 16)
	if err != nil {
		t.Fatal(err)
	}
	packet := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-a", packet, time.Now()); err != nil {
		t.Fatal(err)
	}
	configuration.Enabled = false
	if err := router.ApplyPolicy(configuration); err != nil {
		t.Fatal(err)
	}
	if len(router.flows) != 0 || len(router.nodeFlows) != 0 {
		t.Fatal("disabled policy retained flow ownership")
	}
	if _, err := router.RouteClientPacket("client-a", packet, time.Now()); !errors.Is(err, ErrFlowRejected) {
		t.Fatalf("disabled route: %v", err)
	}
}

func TestAcknowledgementCannotPublishReplacedPool(t *testing.T) {
	broker := NewPoolBroker()
	defer broker.Close()
	spec := PoolSpec{ClientID: "client", SessionID: "session", VirtualIP: "172.20.0.2",
		PoolGeneration: 1, ChannelCount: 1, MTU: 1150, WriteTimeout: time.Second}
	offers, err := broker.Prepare(spec, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server, peer := net.Pipe()
	defer peer.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- broker.Bind(context.Background(), server, protocol.BindVNetChannel{
			ClientID: "client", SessionID: "session", VirtualIP: spec.VirtualIP,
			PoolGeneration: 1, ChannelCount: 1, Ticket: offers[0].Ticket,
		}, authentication.Context{}, func() error { close(entered); <-release; return nil }, nil)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("acknowledgement did not start")
	}
	spec.PoolGeneration = 2
	if _, err := broker.Prepare(spec, time.Minute); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case err := <-finished:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("stale acknowledgement: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stale binding did not stop")
	}
	if _, active := broker.Active("client"); active {
		t.Fatal("stale pool became active")
	}
	broker.mutex.Lock()
	defer broker.mutex.Unlock()
	if broker.pending["client"] == nil || broker.pending["client"].spec.PoolGeneration != 2 {
		t.Fatal("stale acknowledgement removed replacement")
	}
}
