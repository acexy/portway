package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/vnet"
)

func TestVNetDisableRevokesBeforeBlockedNotice(t *testing.T) {
	configuration := config.DefaultServer().VirtualNetwork
	configuration.Enabled = true
	configuration.PacketChannels = 1
	configuration.Nodes = []config.VNetNodeConfig{
		{ClientID: "client-a", IP: "172.20.0.2"},
		{ClientID: "client-b", IP: "172.20.0.3", Ports: config.VNetPortPermissions{
			TCP: config.ForwardPortPermission{PortRanges: []config.PortRange{{Start: 80, End: 80}}},
		}},
	}
	router, err := vnet.NewRouter(configuration, 16)
	if err != nil {
		t.Fatal(err)
	}
	notice := &pausedPeerNotice{started: make(chan struct{}), resume: make(chan struct{})}
	runtime := &serverVNetRuntime{configuration: configuration, router: router, broker: vnet.NewPoolBroker(),
		sessions: map[string]serverVNetSession{
			"client-a": {sessionID: "session-a", poolGeneration: 1, writer: control.NewWriter(notice)},
			"client-b": {sessionID: "session-b", poolGeneration: 2, writer: control.NewWriter(discardConnection{})},
		},
	}
	defer runtime.broker.Close()
	offers, err := runtime.broker.Prepare(vnet.PoolSpec{ClientID: "client-a", SessionID: "session-a",
		VirtualIP: "172.20.0.2", PoolGeneration: 1, ChannelCount: 1, MTU: 1150, WriteTimeout: time.Second}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	connection, peer := net.Pipe()
	defer peer.Close()
	active := make(chan struct{})
	bound := make(chan error, 1)
	go func() {
		bound <- runtime.broker.Bind(context.Background(), connection, protocol.BindVNetChannel{
			ClientID: "client-a", SessionID: "session-a", VirtualIP: "172.20.0.2",
			PoolGeneration: 1, ChannelCount: 1, Ticket: offers[0].Ticket,
		}, authentication.Context{}, nil, func(*vnet.Pool) { close(active) })
	}()
	select {
	case <-active:
	case <-time.After(time.Second):
		t.Fatal("pool did not activate")
	}
	candidate := configuration
	candidate.Enabled = false
	done := make(chan struct{})
	go func() { runtime.applyConfiguration(candidate, 2); close(done) }()
	defer func() { close(notice.resume); <-done }()
	select {
	case <-notice.started:
	case <-time.After(time.Second):
		t.Fatal("notice did not start")
	}
	if _, exists := runtime.broker.Active("client-a"); exists {
		t.Fatal("blocked notice retained local pool")
	}
	_, err = router.AuthorizePeerFlow("client-a", vnet.Flow{Protocol: 6,
		SourceIP: netip.MustParseAddr("172.20.0.2"), SourcePort: 50000,
		DestinationIP: netip.MustParseAddr("172.20.0.3"), DestinationPort: 80, TCPFlags: 2}, time.Now())
	if !errors.Is(err, vnet.ErrFlowRejected) {
		t.Fatalf("disabled router still authorizes traffic: %v", err)
	}
	select {
	case <-bound:
	case <-time.After(time.Second):
		t.Fatal("local pool did not release")
	}
}
