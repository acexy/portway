package server

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/vnet"
)

func TestVNetDestinationFailureDoesNotFailSource(t *testing.T) {
	configuration := config.DefaultServer().VirtualNetwork
	configuration.PacketChannels = 1
	configuration.Nodes = []config.VNetNodeConfig{
		{ClientID: "source", IP: "172.20.0.2"},
		{ClientID: "target", IP: "172.20.0.3", Ports: config.VNetPortPermissions{
			TCP: config.ForwardPortPermission{PortRanges: []config.PortRange{{Start: 80, End: 80}}},
		}},
	}
	router, err := vnet.NewRouter(configuration, 16)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &serverVNetRuntime{router: router, broker: vnet.NewPoolBroker()}
	defer runtime.broker.Close()
	packet := make([]byte, 40)
	packet[0], packet[9], packet[32], packet[33] = 0x45, 6, 0x50, 2
	binary.BigEndian.PutUint16(packet[2:4], 40)
	copy(packet[12:16], []byte{172, 20, 0, 2})
	copy(packet[16:20], []byte{172, 20, 0, 3})
	binary.BigEndian.PutUint16(packet[20:22], 50000)
	binary.BigEndian.PutUint16(packet[22:24], 80)
	if err := runtime.routeClientPacket("source", packet); err != nil {
		t.Fatalf("offline target failed source: %v", err)
	}
	spec := vnet.PoolSpec{ClientID: "target", SessionID: "session", VirtualIP: "172.20.0.3",
		PoolGeneration: 1, ChannelCount: 1, MTU: 1280, WriteTimeout: 20 * time.Millisecond}
	offers, err := runtime.broker.Prepare(spec, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	connection, peer := net.Pipe()
	defer peer.Close()
	active := make(chan struct{})
	bound := make(chan error, 1)
	go func() {
		bound <- runtime.broker.Bind(context.Background(), connection, protocol.BindVNetChannel{
			ClientID: spec.ClientID, SessionID: spec.SessionID, VirtualIP: spec.VirtualIP,
			PoolGeneration: 1, ChannelCount: 1, Ticket: offers[0].Ticket,
		}, authentication.Context{}, nil, func(*vnet.Pool) { close(active) })
	}()
	<-active
	if err := runtime.routeClientPacket("source", packet); err != nil {
		t.Fatalf("blocked target failed source: %v", err)
	}
	select {
	case <-bound:
	case <-time.After(time.Second):
		t.Fatal("blocked target pool was not closed")
	}
}

func TestVNetDelayedStatusDoesNotRejectControlSession(t *testing.T) {
	runtime := &serverVNetRuntime{sessions: map[string]serverVNetSession{
		"client": {sessionID: "session", poolGeneration: 2, configGeneration: 2, writer: control.NewWriter(discardConnection{})},
	}}
	for _, state := range []protocol.VNetState{protocol.VNetStateReady, protocol.VNetStateFailed} {
		if err := runtime.activate("client", "session", protocol.VNetStatus{
			State: state, PoolGeneration: 1, ConfigGeneration: 1,
		}); err != nil {
			t.Fatalf("delayed %s rejected current session: %v", state, err)
		}
	}
}
