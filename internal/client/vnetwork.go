package client

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
	"github.com/acexy/portway/internal/vnet"
)

type clientVNetManager struct {
	context     context.Context
	cancel      context.CancelFunc
	logger      *logging.Logger
	clientID    string
	sessionID   string
	writer      *control.Writer
	transport   transport.ClientSession
	mutex       sync.Mutex
	assignment  protocol.VNetAssignment
	device      vnet.Device
	offers      map[uint8]protocol.OpenVNetChannel
	activated   bool
	channels    []transport.Stream
	waitGroup   sync.WaitGroup
	deviceWrite sync.Mutex
}

func newClientVNetManager(
	parent context.Context,
	logger *logging.Logger,
	clientID string,
	sessionID string,
	writer *control.Writer,
	transportSession transport.ClientSession,
) *clientVNetManager {
	ctx, cancel := context.WithCancel(parent)
	return &clientVNetManager{
		context: ctx, cancel: cancel, logger: logger,
		clientID: clientID, sessionID: sessionID, writer: writer, transport: transportSession,
		offers: make(map[uint8]protocol.OpenVNetChannel),
	}
}

func (manager *clientVNetManager) applyAssignment(assignment protocol.VNetAssignment) error {
	if err := validateVNetAssignment(assignment, manager.clientID); err != nil {
		return fmt.Errorf("%w: %v", transport.ErrProtocol, err)
	}
	manager.closeRuntime()
	manager.mutex.Lock()
	manager.assignment = assignment
	manager.offers = make(map[uint8]protocol.OpenVNetChannel)
	manager.activated = false
	manager.mutex.Unlock()
	if assignment.State != protocol.VNetStateActive {
		return manager.reportStatus(assignment.State, "")
	}
	device, err := vnet.PrepareNetwork(vnet.NetworkSpec{
		Role: vnet.NetworkRoleClient, CIDR: assignment.CIDR, LocalIP: assignment.ClientIP,
		ServerIP: assignment.ServerIP, MTU: assignment.MTU, OwnerUID: -1,
	})
	if err != nil {
		manager.logger.WarnWithFields("VNet network installation is required", err, map[string]any{
			"event": "vnet_installation_required",
		})
		return manager.reportStatus(protocol.VNetStateInstallationRequired, "device_unavailable")
	}
	manager.mutex.Lock()
	manager.device = device
	manager.mutex.Unlock()
	return nil
}

func (manager *clientVNetManager) activate(activation protocol.VNetActivate) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.device == nil || manager.assignment.State != protocol.VNetStateActive ||
		activation.PoolGeneration != manager.assignment.PoolGeneration ||
		activation.ConfigGeneration != manager.assignment.ConfigGeneration {
		return fmt.Errorf("%w: invalid VNet activation", transport.ErrProtocol)
	}
	manager.activated = true
	return nil
}

func (manager *clientVNetManager) offer(offer protocol.OpenVNetChannel) error {
	manager.mutex.Lock()
	assignment := manager.assignment
	if assignment.State != protocol.VNetStateActive || manager.device == nil || !manager.activated {
		manager.mutex.Unlock()
		return nil
	}
	if offer.PoolGeneration != assignment.PoolGeneration ||
		offer.ChannelCount != assignment.PacketChannels ||
		offer.ChannelIndex >= offer.ChannelCount || offer.ExpiresAtUnixMS <= time.Now().UnixMilli() {
		manager.mutex.Unlock()
		return fmt.Errorf("%w: invalid VNet channel offer", transport.ErrProtocol)
	}
	if _, duplicate := manager.offers[offer.ChannelIndex]; duplicate {
		manager.mutex.Unlock()
		return fmt.Errorf("%w: duplicate VNet channel offer", transport.ErrProtocol)
	}
	manager.offers[offer.ChannelIndex] = offer
	complete := len(manager.offers) == int(assignment.PacketChannels)
	manager.mutex.Unlock()
	if complete {
		manager.waitGroup.Go(func() { manager.openPool(assignment) })
	}
	return nil
}

func (manager *clientVNetManager) openPool(assignment protocol.VNetAssignment) {
	channels := make([]transport.Stream, int(assignment.PacketChannels))
	for index := range channels {
		manager.mutex.Lock()
		offer := manager.offers[uint8(index)]
		manager.mutex.Unlock()
		stream, err := manager.transport.OpenDataStream(manager.context)
		if err == nil {
			err = protocol.WriteControl(stream, protocol.MessageBindVNetChannel, protocol.BindVNetChannel{
				ClientID: manager.clientID, SessionID: manager.sessionID,
				TransportGeneration: uint64(manager.transport.Generation()), VirtualIP: assignment.ClientIP,
				PoolGeneration: offer.PoolGeneration, ChannelIndex: offer.ChannelIndex,
				ChannelCount: offer.ChannelCount, Ticket: offer.Ticket,
			})
		}
		if err == nil {
			var envelope protocol.Envelope
			envelope, err = protocol.ReadControl(stream)
			if err == nil && envelope.Type != protocol.MessageVNetBindResult {
				err = errors.New("unexpected VNet bind response")
			}
			if err == nil {
				var result protocol.VNetBindResult
				err = protocol.DecodePayload(envelope, &result)
				if err == nil && (result.Status != protocol.LinkStatusAccepted ||
					result.PoolGeneration != offer.PoolGeneration || result.ChannelIndex != offer.ChannelIndex) {
					err = errors.New("VNet channel binding was rejected")
				}
			}
		}
		if err != nil {
			if stream != nil {
				stream.Close()
			}
			closeVNetChannels(channels)
			_ = manager.reportStatus(protocol.VNetStateFailed, "channel_bind_failed")
			return
		}
		_ = stream.SetDeadline(time.Time{})
		channels[index] = stream
	}
	manager.mutex.Lock()
	if manager.assignment.PoolGeneration != assignment.PoolGeneration || manager.context.Err() != nil {
		manager.mutex.Unlock()
		closeVNetChannels(channels)
		return
	}
	manager.channels = channels
	device := manager.device
	manager.mutex.Unlock()
	_ = manager.reportStatus(protocol.VNetStateActive, "")
	manager.waitGroup.Go(func() { manager.readDevice(device, assignment, channels) })
	for _, stream := range channels {
		channel := stream
		manager.waitGroup.Go(func() { manager.readChannel(device, assignment, channel) })
	}
}

func (manager *clientVNetManager) readDevice(
	device vnet.Device,
	assignment protocol.VNetAssignment,
	channels []transport.Stream,
) {
	buffer := make([]byte, int(assignment.MTU))
	for {
		length, err := device.ReadPacket(buffer)
		if err != nil {
			manager.failPool(assignment.PoolGeneration, "device_read_failed")
			return
		}
		packet := append([]byte(nil), buffer[:length]...)
		flow, err := vnet.ParseIPv4(packet)
		if err != nil || flow.SourceIP.String() != assignment.ClientIP {
			continue
		}
		index, err := vnet.ChannelIndex(flow, assignment.PacketChannels)
		if err != nil || vnet.WritePacket(channels[index], packet, assignment.MTU) != nil {
			manager.failPool(assignment.PoolGeneration, "channel_write_failed")
			return
		}
	}
}

func (manager *clientVNetManager) readChannel(
	device vnet.Device,
	assignment protocol.VNetAssignment,
	channel transport.Stream,
) {
	for {
		packet, err := vnet.ReadPacket(channel, assignment.MTU)
		if err != nil {
			manager.failPool(assignment.PoolGeneration, "channel_read_failed")
			return
		}
		flow, err := vnet.ParseIPv4(packet)
		if err != nil || flow.DestinationIP.String() != assignment.ClientIP {
			continue
		}
		manager.deviceWrite.Lock()
		written, writeError := device.WritePacket(packet)
		manager.deviceWrite.Unlock()
		if writeError != nil || written != len(packet) {
			manager.failPool(assignment.PoolGeneration, "device_write_failed")
			return
		}
	}
}

func (manager *clientVNetManager) failPool(generation uint64, code string) {
	manager.mutex.Lock()
	if manager.assignment.PoolGeneration != generation || len(manager.channels) == 0 {
		manager.mutex.Unlock()
		return
	}
	channels := manager.channels
	manager.channels = nil
	device := manager.device
	manager.device = nil
	manager.activated = false
	manager.mutex.Unlock()
	closeVNetChannels(channels)
	if device != nil {
		_ = device.Close()
	}
	_ = manager.reportStatus(protocol.VNetStateFailed, code)
}

func (manager *clientVNetManager) deactivate(deactivation protocol.VNetDeactivate) error {
	manager.mutex.Lock()
	if deactivation.PoolGeneration != 0 && manager.assignment.PoolGeneration != 0 &&
		deactivation.PoolGeneration != manager.assignment.PoolGeneration {
		manager.mutex.Unlock()
		return fmt.Errorf("%w: VNet pool generation mismatch", transport.ErrProtocol)
	}
	manager.mutex.Unlock()
	manager.closeRuntime()
	return manager.reportStatus(protocol.VNetStateDisabled, string(deactivation.Reason))
}

func (manager *clientVNetManager) reportStatus(state protocol.VNetState, code string) error {
	manager.mutex.Lock()
	assignment := manager.assignment
	manager.mutex.Unlock()
	return manager.writer.Write(protocol.MessageVNetStatus, protocol.VNetStatus{
		State: state, PoolGeneration: assignment.PoolGeneration,
		ConfigGeneration: assignment.ConfigGeneration, Code: code,
	})
}

func (manager *clientVNetManager) closeRuntime() {
	manager.mutex.Lock()
	channels := manager.channels
	manager.channels = nil
	device := manager.device
	manager.device = nil
	manager.mutex.Unlock()
	closeVNetChannels(channels)
	if device != nil {
		device.Close()
	}
}

func (manager *clientVNetManager) close() {
	manager.cancel()
	manager.closeRuntime()
	manager.waitGroup.Wait()
}

func closeVNetChannels(channels []transport.Stream) {
	for _, channel := range channels {
		if channel != nil {
			channel.Close()
		}
	}
}

func validateVNetAssignment(assignment protocol.VNetAssignment, clientID string) error {
	prefix, err := netip.ParsePrefix(assignment.CIDR)
	if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix != prefix.Masked() {
		return errors.New("invalid VNet CIDR")
	}
	clientIP, clientError := netip.ParseAddr(assignment.ClientIP)
	serverIP, serverError := netip.ParseAddr(assignment.ServerIP)
	if clientError != nil || serverError != nil || !prefix.Contains(clientIP) ||
		!prefix.Contains(serverIP) || clientIP == serverIP {
		return errors.New("invalid VNet address assignment")
	}
	if clientID == "" || assignment.MTU < 576 || assignment.PacketChannels < 1 ||
		assignment.PacketChannels > 8 || assignment.PoolGeneration == 0 || assignment.ConfigGeneration == 0 {
		return errors.New("invalid VNet assignment limits")
	}
	switch assignment.State {
	case protocol.VNetStateDisabled, protocol.VNetStateInstallationRequired,
		protocol.VNetStateActive, protocol.VNetStateFailed:
		return nil
	default:
		return errors.New("invalid VNet assignment state")
	}
}
