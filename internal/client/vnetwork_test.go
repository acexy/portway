package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/vnet"
)

func TestClientVNetPacketWritesAreSerializedPerChannel(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	stream := &observedVNetStream{Conn: client}
	go func() { _, _ = io.Copy(io.Discard, server) }()
	writer := vnet.NewPacketWriter(context.Background(), stream, 1280, time.Second)
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for range 2 {
		waitGroup.Go(func() {
			<-start
			if err := writer.Send([]byte{1}); err != nil {
				t.Errorf("write VNet packet: %v", err)
			}
		})
	}
	close(start)
	waitGroup.Wait()
	if stream.overlapped.Load() {
		t.Fatal("one VNet channel was written concurrently")
	}
}

func TestValidateVNetAssignment(t *testing.T) {
	valid := protocol.VNetAssignment{
		NetworkMode: "tun",
		CIDR: "172.20.0.0/16", ClientIP: "172.20.0.2", ServerIP: "172.20.0.1",
		MTU: 1280, PacketChannels: 4, TransportGeneration: 1,
		PoolGeneration: 3, ConfigGeneration: 2,
		State: protocol.VNetStateEnabled,
	}
	if err := validateVNetAssignment(valid, "managed-a"); err != nil {
		t.Fatalf("validate assignment: %v", err)
	}
	invalid := valid
	invalid.PacketChannels = 9
	if err := validateVNetAssignment(invalid, "managed-a"); err == nil {
		t.Fatal("expected excessive channel count to be rejected")
	}
	invalid = valid
	invalid.ClientIP = invalid.ServerIP
	if err := validateVNetAssignment(invalid, "managed-a"); err == nil {
		t.Fatal("expected duplicate server and client address to be rejected")
	}
	invalid = valid
	invalid.TransportGeneration = 0
	if err := validateVNetAssignment(invalid, "managed-a"); err == nil {
		t.Fatal("expected missing transport generation to be rejected")
	}
}

func TestVNetReplacementAssignmentPreservesCompatibleDevice(t *testing.T) {
	device := &countingVNetDevice{}
	manager := &clientVNetManager{
		clientID: "managed-a",
		writer:   control.NewWriter(&bytes.Buffer{}),
		assignment: protocol.VNetAssignment{
			NetworkMode: "tun",
			CIDR: "172.20.0.0/16", ClientIP: "172.20.0.2", ServerIP: "172.20.0.1",
			MTU: 1280, PacketChannels: 1, TransportGeneration: 1,
			PoolGeneration: 1, ConfigGeneration: 1, State: protocol.VNetStateEnabled,
		},
		device: device,
		offers: make(map[uint8]protocol.OpenVNetChannel),
	}
	replacement := manager.assignment
	replacement.PoolGeneration = 2
	replacement.ConfigGeneration = 2
	if err := manager.applyAssignment(replacement); err != nil {
		t.Fatalf("apply replacement assignment: %v", err)
	}
	if manager.device != device {
		t.Fatal("compatible replacement assignment discarded the VNet device")
	}
	if device.closeCount.Load() != 0 {
		t.Fatal("compatible replacement assignment closed the VNet device")
	}
}

func TestVNetRecoveringDeactivatePreservesDevice(t *testing.T) {
	device := &countingVNetDevice{}
	manager := &clientVNetManager{
		writer: control.NewWriter(&bytes.Buffer{}),
		assignment: protocol.VNetAssignment{
			PoolGeneration: 1, ConfigGeneration: 1,
		},
		device: device,
	}
	if err := manager.deactivate(protocol.VNetDeactivate{
		PoolGeneration: 1, ConfigGeneration: 2,
		Reason: protocol.VNetDeactivatePolicyChanged,
	}); err != nil {
		t.Fatalf("deactivate for recovery: %v", err)
	}
	if manager.device != device || device.closeCount.Load() != 0 {
		t.Fatal("recovering deactivate closed the VNet device")
	}
}

func TestVNetActivationRequiresExactGenerations(t *testing.T) {
	manager := &clientVNetManager{
		assignment: protocol.VNetAssignment{
			State: protocol.VNetStateEnabled, PoolGeneration: 8, ConfigGeneration: 5,
		},
		device: inertVNetDevice{},
	}
	if err := manager.activate(protocol.VNetActivate{PoolGeneration: 8, ConfigGeneration: 5}); err != nil {
		t.Fatalf("activate exact generation: %v", err)
	}
	if !manager.activated {
		t.Fatal("expected manager to become activated")
	}
	if err := manager.activate(protocol.VNetActivate{PoolGeneration: 7, ConfigGeneration: 5}); err == nil {
		t.Fatal("expected stale pool generation to be rejected")
	}
}

type inertVNetDevice struct{}

func (inertVNetDevice) Name() string                    { return "test0" }
func (inertVNetDevice) ReadPacket([]byte) (int, error)  { return 0, errors.New("closed") }
func (inertVNetDevice) WritePacket([]byte) (int, error) { return 0, errors.New("closed") }
func (inertVNetDevice) Close() error                    { return nil }

type countingVNetDevice struct {
	closeCount atomic.Int32
}

type observedVNetStream struct {
	net.Conn
	active     atomic.Int32
	overlapped atomic.Bool
}

func (stream *observedVNetStream) Write(packet []byte) (int, error) {
	if stream.active.Add(1) != 1 {
		stream.overlapped.Store(true)
	}
	defer stream.active.Add(-1)
	time.Sleep(time.Millisecond)
	return stream.Conn.Write(packet)
}

func (stream *observedVNetStream) CloseWrite() error { return stream.Close() }

func (*countingVNetDevice) Name() string                    { return "test0" }
func (*countingVNetDevice) ReadPacket([]byte) (int, error)  { return 0, errors.New("closed") }
func (*countingVNetDevice) WritePacket([]byte) (int, error) { return 0, errors.New("closed") }
func (device *countingVNetDevice) Close() error {
	device.closeCount.Add(1)
	return nil
}
