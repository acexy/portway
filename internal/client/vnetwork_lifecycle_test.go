package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
	"github.com/acexy/portway/internal/vnet"
)

func TestWindowsVNetNetworkConflictReportsFailureAndStopsClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var status bytes.Buffer
	manager := &clientVNetManager{
		context: ctx, cancel: cancel, clientID: "managed-a", logger: logging.New("test"),
		writer: control.NewWriter(&status), failures: make(chan error, 1), exitOnConflict: true,
		prepareNetwork: func(context.Context, vnet.NetworkSpec) (vnet.Device, error) {
			return nil, fmt.Errorf("%w: VNet CIDR overlaps an existing route", vnet.ErrForeignResource)
		},
	}
	defer manager.close()
	if err := manager.applyAssignment(lifecycleVNetAssignment()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-manager.failures:
		if !transport.IsPermanent(err) || !errors.Is(err, vnet.ErrForeignResource) {
			t.Fatalf("conflict error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("network conflict did not stop the Windows client")
	}
	if !bytes.Contains(status.Bytes(), []byte("network_conflict")) {
		t.Fatalf("reported status = %q", status.String())
	}
}

func lifecycleVNetAssignment() protocol.VNetAssignment {
	return protocol.VNetAssignment{
		NetworkMode: "tun", CIDR: "172.20.0.0/16", ClientIP: "172.20.0.2", ServerIP: "172.20.0.1",
		MTU: 1280, PacketChannels: 1, TransportGeneration: 1,
		PoolGeneration: 1, ConfigGeneration: 1, State: protocol.VNetStateEnabled,
	}
}

func TestVNetAddressChangeClosesOldDeviceBeforeInstallation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	oldDevice := &countingVNetDevice{}
	newDevice := &queuedVNetDevice{packets: make(chan []byte), closed: make(chan struct{})}
	manager := &clientVNetManager{context: ctx, cancel: cancel, clientID: "managed-a",
		assignment: lifecycleVNetAssignment(), device: oldDevice,
		logger: logging.New("test"), writer: control.NewWriter(&bytes.Buffer{})}
	defer manager.close()
	prepared := make(chan vnet.NetworkSpec, 1)
	manager.prepareNetwork = func(ctx context.Context, spec vnet.NetworkSpec) (vnet.Device, error) {
		if oldDevice.closeCount.Load() != 1 {
			t.Error("old device was still held when migration started")
		}
		prepared <- spec
		return newDevice, nil
	}
	assignment := manager.assignment
	assignment.PoolGeneration++
	assignment.CIDR, assignment.ClientIP, assignment.ServerIP = "172.21.0.0/16", "172.21.0.2", "172.21.0.1"
	if err := manager.applyAssignment(assignment); err != nil {
		t.Fatal(err)
	}
	select {
	case spec := <-prepared:
		if spec.CIDR != assignment.CIDR || spec.LocalIP != assignment.ClientIP || spec.ServerIP != assignment.ServerIP {
			t.Fatal("client installation did not receive its latest assignment")
		}
	case <-time.After(time.Second):
		t.Fatal("client address change did not trigger installation")
	}
}

type migratingClientVNetDevice struct {
	countingVNetDevice
	migrations chan vnet.NetworkSpec
}

func (device *migratingClientVNetDevice) MigrateNetwork(
	_ context.Context,
	_ vnet.NetworkSpec,
	next vnet.NetworkSpec,
) error {
	device.migrations <- next
	return nil
}

func TestVNetAddressChangeMigratesSupportedDeviceInPlace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	device := &migratingClientVNetDevice{migrations: make(chan vnet.NetworkSpec, 1)}
	manager := &clientVNetManager{context: ctx, cancel: cancel, clientID: "managed-a",
		assignment: lifecycleVNetAssignment(), device: device,
		logger: logging.New("test"), writer: control.NewWriter(&bytes.Buffer{})}
	defer manager.close()
	assignment := manager.assignment
	assignment.PoolGeneration++
	assignment.CIDR, assignment.ClientIP, assignment.ServerIP = "172.21.0.0/16", "172.21.0.2", "172.21.0.1"
	if err := manager.applyAssignment(assignment); err != nil {
		t.Fatal(err)
	}
	select {
	case spec := <-device.migrations:
		if spec.CIDR != assignment.CIDR || spec.LocalIP != assignment.ClientIP {
			t.Fatalf("migration target = %+v", spec)
		}
	case <-time.After(time.Second):
		t.Fatal("client address change did not migrate the live device")
	}
	manager.mutex.Lock()
	active := manager.device
	manager.mutex.Unlock()
	if active != device || device.closeCount.Load() != 0 {
		t.Fatal("client migration replaced or closed the live device")
	}
}

func TestVNetPreparationIsAsyncAndDiscardsCancelledDevice(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	manager := &clientVNetManager{context: ctx, cancel: cancel, clientID: "managed-a", writer: control.NewWriter(&bytes.Buffer{})}
	device := &countingVNetDevice{}
	started := make(chan struct{})
	manager.prepareNetwork = func(ctx context.Context, _ vnet.NetworkSpec) (vnet.Device, error) {
		close(started)
		<-ctx.Done()
		return device, nil
	}
	returned := make(chan error, 1)
	go func() { returned <- manager.applyAssignment(lifecycleVNetAssignment()) }()
	select {
	case err := <-returned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("assignment blocked on system authorization")
	}
	<-started
	manager.close()
	if manager.device != nil || device.closeCount.Load() != 1 {
		t.Fatal("cancelled preparation published or leaked its device")
	}
}

type queuedVNetDevice struct {
	packets chan []byte
	closed  chan struct{}
	reads   atomic.Int32
	once    sync.Once
}

func (*queuedVNetDevice) Name() string { return "test0" }
func (device *queuedVNetDevice) ReadPacket(packet []byte) (int, error) {
	device.reads.Add(1)
	select {
	case value := <-device.packets:
		return copy(packet, value), nil
	case <-device.closed:
		return 0, net.ErrClosed
	}
}
func (*queuedVNetDevice) WritePacket(packet []byte) (int, error) { return len(packet), nil }
func (device *queuedVNetDevice) Close() error {
	device.once.Do(func() { close(device.closed) })
	return nil
}

func TestVNetDeviceReaderUsesReplacementPool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	device := &queuedVNetDevice{packets: make(chan []byte), closed: make(chan struct{})}
	manager := &clientVNetManager{context: ctx, cancel: cancel, clientID: "managed-a",
		assignment: lifecycleVNetAssignment(), device: device, writer: control.NewWriter(&bytes.Buffer{})}
	defer manager.close()
	initial := manager.assignment
	manager.waitGroup.Go(func() { manager.readDevice(device, initial) })
	replacement := initial
	replacement.PoolGeneration++
	if err := manager.applyAssignment(replacement); err != nil {
		t.Fatal(err)
	}
	connection, peer := net.Pipe()
	defer peer.Close()
	stream := &observedVNetStream{Conn: connection}
	manager.mutex.Lock()
	manager.channels = []transport.Stream{stream}
	manager.channelWrites = []*vnet.PacketWriter{vnet.NewPacketWriter(ctx, stream, 1280, time.Second)}
	manager.mutex.Unlock()
	packet := make([]byte, 28)
	packet[0], packet[9] = 0x45, 17
	binary.BigEndian.PutUint16(packet[2:4], 28)
	copy(packet[12:16], []byte{172, 20, 0, 2})
	copy(packet[16:20], []byte{172, 20, 0, 3})
	binary.BigEndian.PutUint16(packet[20:22], 50000)
	binary.BigEndian.PutUint16(packet[22:24], 53)
	binary.BigEndian.PutUint16(packet[24:26], 8)
	device.packets <- packet
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if received, err := vnet.ReadPacket(peer, 1280); err != nil || !bytes.Equal(received, packet) {
		t.Fatalf("replacement pool packet = %v, error = %v", received, err)
	}
	manager.failPool(initial.PoolGeneration, "old_failure")
	manager.mutex.Lock()
	remaining := len(manager.channels)
	manager.mutex.Unlock()
	if remaining != 1 {
		t.Fatal("old generation failure closed the new pool")
	}
}
