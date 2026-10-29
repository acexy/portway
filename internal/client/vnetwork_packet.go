package client

import (
	"errors"
	"os"
	"time"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
	"github.com/acexy/portway/internal/vnet"
	packetdata "github.com/acexy/portway/internal/vnet/packet"
	"github.com/acexy/portway/internal/vnet/system"
)

func (manager *clientVNetManager) readDevice(
	device system.Device,
	assignment protocol.VNetAssignment,
) {
	buffer := make([]byte, int(assignment.MTU))
	for {
		length, err := device.ReadPacket(buffer)
		if err != nil {
			manager.mutex.Lock()
			if manager.device != device {
				manager.mutex.Unlock()
				return
			}
			current := manager.assignment
			hadChannels := len(manager.channels) != 0
			userspaceTCP := manager.userspaceTCP
			manager.device = nil
			manager.userspaceTCP = nil
			manager.mutex.Unlock()
			manager.failPool(current.PoolGeneration, vnetFailureDeviceReadFailed)
			if !hadChannels && manager.context.Err() == nil {
				_ = manager.reportAssignmentStatus(current, protocol.VNetStateFailed, string(vnetFailureDeviceReadFailed))
			}
			_ = device.Close()
			if userspaceTCP != nil {
				_ = userspaceTCP.Close()
			}
			return
		}
		packet := append([]byte(nil), buffer[:length]...)
		manager.mutex.Lock()
		if manager.device != device {
			migrating := manager.migratingDevice == device
			manager.mutex.Unlock()
			if migrating {
				continue
			}
			return
		}
		current := manager.assignment
		userspaceTCP := manager.userspaceTCP
		manager.mutex.Unlock()
		flow, err := packetdata.ParseIPv4(packet)
		if err != nil || flow.SourceIP.String() != current.ClientIP {
			continue
		}
		if userspaceTCP != nil && !userspaceTCP.ObserveHostPacket(packet) {
			continue
		}
		_ = manager.sendUserspaceTCPPacket(packet)
	}
}

func (manager *clientVNetManager) readChannel(
	device system.Device,
	assignment protocol.VNetAssignment,
	channel transport.Stream,
) {
	for {
		packet, err := vnet.ReadPacket(channel, assignment.MTU)
		if err != nil {
			manager.failPool(assignment.PoolGeneration, vnetFailureChannelReadFailed)
			return
		}
		flow, err := packetdata.ParseIPv4(packet)
		if err != nil || flow.DestinationIP.String() != assignment.ClientIP {
			continue
		}
		manager.mutex.Lock()
		if manager.assignment.PoolGeneration != assignment.PoolGeneration || manager.device != device || len(manager.channels) == 0 {
			manager.mutex.Unlock()
			return
		}
		userspaceTCP := manager.userspaceTCP
		peerEndpoint := manager.peerEndpoint
		manager.mutex.Unlock()
		if peerEndpoint != nil {
			peerEndpoint.MarkRelay(flow, time.Now())
		}
		if userspaceTCP != nil && userspaceTCP.Handle(packet) {
			continue
		}
		manager.deviceWrite.Lock()
		written, writeError := device.WritePacket(packet)
		manager.deviceWrite.Unlock()
		if writeError != nil || written != len(packet) {
			manager.failPool(assignment.PoolGeneration, vnetFailureDeviceWriteFailed)
			return
		}
	}
}

func (manager *clientVNetManager) sendUserspaceTCPPacket(packet []byte) error {
	flow, err := packetdata.ParseIPv4(packet)
	if err != nil {
		return err
	}
	manager.mutex.Lock()
	assignment := manager.assignment
	peerEndpoint := manager.peerEndpoint
	// Published pool entries are immutable; replacement only swaps the slice header.
	channels := manager.channels
	manager.mutex.Unlock()
	if peerEndpoint != nil {
		if sent, sendError := peerEndpoint.Send(flow, packet, time.Now()); sent {
			return sendError
		}
		peerEndpoint.MarkRelay(flow, time.Now())
	}
	index, err := packetdata.ChannelIndex(flow, assignment.PacketChannels)
	if err != nil || int(index) >= len(channels) {
		return errors.New("VNet userspace stack pool is unavailable")
	}
	err = channels[index].writer.Send(packet)
	if err != nil {
		code := vnetFailureChannelWriteFailed
		if errors.Is(err, os.ErrDeadlineExceeded) {
			code = vnetFailureChannelWriteTimeout
		}
		manager.failPool(assignment.PoolGeneration, code)
	}
	return err
}
