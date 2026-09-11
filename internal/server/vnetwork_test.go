package server

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

func TestVNetOffersAreIssuedOnlyAfterClientReadiness(t *testing.T) {
	configuration := config.DefaultServer().VirtualNetwork
	configuration.Enabled = true
	configuration.PacketChannels = 1
	configuration.ServerPorts.TCP.PortRanges = []config.PortRange{{Start: 22, End: 22}}
	configuration.Nodes = []config.VNetNodeConfig{{ClientID: "managed-a", IP: "172.20.0.2"}}
	device := newBlockingVNetDevice()
	runtime := newServerVNetRuntime(context.Background(), logging.New("test"), configuration, device)
	defer runtime.Close()
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	runtime.attach("managed-a", "session-a", transport.Generation(1), authentication.Context{
		Mode: authentication.ModeManaged, ClientID: "managed-a",
	}, control.NewWriter(serverConnection))

	assigned := make(chan error, 1)
	go func() { assigned <- runtime.assign("managed-a", "session-a") }()
	envelope, err := protocol.ReadControl(clientConnection)
	if err != nil || envelope.Type != protocol.MessageVNetAssignment {
		t.Fatalf("read VNet assignment: type=%s err=%v", envelope.Type, err)
	}
	var assignment protocol.VNetAssignment
	if err := protocol.DecodePayload(envelope, &assignment); err != nil {
		t.Fatal(err)
	}
	if assignment.TransportGeneration != 1 {
		t.Fatalf("unexpected transport generation: %d", assignment.TransportGeneration)
	}
	if err := <-assigned; err != nil {
		t.Fatal(err)
	}

	activated := make(chan error, 1)
	go func() {
		activated <- runtime.activate("managed-a", "session-a", protocol.VNetStatus{
			State: protocol.VNetStateReady, PoolGeneration: assignment.PoolGeneration,
			ConfigGeneration: assignment.ConfigGeneration,
		})
	}()
	activationEnvelope, err := protocol.ReadControl(clientConnection)
	if err != nil || activationEnvelope.Type != protocol.MessageVNetActivate {
		t.Fatalf("read VNet activation: type=%s err=%v", activationEnvelope.Type, err)
	}
	offerEnvelope, err := protocol.ReadControl(clientConnection)
	if err != nil || offerEnvelope.Type != protocol.MessageOpenVNetChannel {
		t.Fatalf("read VNet offer: type=%s err=%v", offerEnvelope.Type, err)
	}
	var offer protocol.OpenVNetChannel
	if err := protocol.DecodePayload(offerEnvelope, &offer); err != nil {
		t.Fatal(err)
	}
	if time.Until(time.UnixMilli(offer.ExpiresAtUnixMS)) < 9*time.Second {
		t.Fatal("VNet offer lifetime started before client readiness")
	}
	if err := <-activated; err != nil {
		t.Fatal(err)
	}
}

type blockingVNetDevice struct {
	closed chan struct{}
}

func newBlockingVNetDevice() *blockingVNetDevice {
	return &blockingVNetDevice{closed: make(chan struct{})}
}

func (*blockingVNetDevice) Name() string { return "test0" }
func (device *blockingVNetDevice) ReadPacket([]byte) (int, error) {
	<-device.closed
	return 0, errors.New("closed")
}
func (*blockingVNetDevice) WritePacket(packet []byte) (int, error) { return len(packet), nil }
func (device *blockingVNetDevice) Close() error {
	select {
	case <-device.closed:
	default:
		close(device.closed)
	}
	return nil
}
