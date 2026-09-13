package client

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
	"github.com/acexy/portway/internal/vnet"
)

const clientVNetChannelWriteTimeout = 5 * time.Second

type clientVNetManager struct {
	context       context.Context
	cancel        context.CancelFunc
	logger        *logging.Logger
	clientID      string
	sessionID     string
	writer        *control.Writer
	transport     transport.ClientSession
	mutex         sync.Mutex
	assignment    protocol.VNetAssignment
	device        vnet.Device
	userspaceTCP  *vnet.UserspaceTCP
	offers        map[uint8]protocol.OpenVNetChannel
	activated     bool
	channels      []transport.Stream
	channelWrites []*vnet.PacketWriter
	waitGroup     sync.WaitGroup
	deviceWrite   sync.Mutex
	prepareMutex sync.Mutex
	prepareCancel context.CancelFunc
	poolCancel context.CancelFunc
	prepareNetwork func(context.Context, vnet.NetworkSpec) (vnet.Device, error)
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
		offers: make(map[uint8]protocol.OpenVNetChannel), prepareNetwork: vnet.PrepareNetworkContext,
	}
}

func (manager *clientVNetManager) applyAssignment(assignment protocol.VNetAssignment) error {
	if err := validateVNetAssignment(assignment, manager.clientID); err != nil {
		return fmt.Errorf("%w: %v", transport.ErrProtocol, err)
	}
	manager.mutex.Lock()
	if manager.prepareCancel != nil {
		manager.prepareCancel()
	}
	if manager.poolCancel != nil {
		manager.poolCancel()
	}
	previous := manager.assignment
	device := manager.device
	userspaceTCP := manager.userspaceTCP
	preserveDevice := device != nil && assignment.State == protocol.VNetStateEnabled &&
		previous.CIDR == assignment.CIDR && previous.ClientIP == assignment.ClientIP &&
		previous.ServerIP == assignment.ServerIP && previous.MTU == assignment.MTU &&
		previous.NetworkMode == assignment.NetworkMode
	channels := manager.channels
	manager.channels = nil
	manager.channelWrites = nil
	if !preserveDevice {
		manager.device = nil
		manager.userspaceTCP = nil
	}
	manager.assignment = assignment
	manager.offers = make(map[uint8]protocol.OpenVNetChannel)
	manager.activated = false
	manager.mutex.Unlock()
	closeVNetChannels(channels)
	if preserveDevice {
		return manager.reportAssignmentStatus(assignment, protocol.VNetStateReady, "")
	}
	ctx, cancel := context.WithCancel(manager.context)
	manager.mutex.Lock()
	manager.prepareCancel = cancel
	manager.mutex.Unlock()
	manager.waitGroup.Go(func() {
		manager.prepareMutex.Lock()
		defer manager.prepareMutex.Unlock()
		if userspaceTCP != nil {
			_ = userspaceTCP.Close()
		}
		if device != nil {
			_ = device.Close()
		}
		if ctx.Err() != nil {
			return
		}
		if assignment.State != protocol.VNetStateEnabled {
			_ = manager.reportAssignmentStatus(assignment, assignment.State, "")
			return
		}
		manager.prepareDevice(ctx, assignment)
	})
	return nil
}

func (manager *clientVNetManager) prepareDevice(ctx context.Context, assignment protocol.VNetAssignment) {
	preparedDevice, err := manager.prepareNetwork(ctx, vnet.NetworkSpec{
		Role: vnet.NetworkRoleClient, CIDR: assignment.CIDR, LocalIP: assignment.ClientIP,
		ServerIP: assignment.ServerIP, MTU: assignment.MTU, OwnerUID: -1,
	})
	if ctx.Err() != nil {
		if preparedDevice != nil {
			_ = preparedDevice.Close()
		}
		return
	}
	if err != nil {
		if errors.Is(err, vnet.ErrForeignResource) || errors.Is(err, vnet.ErrStateMismatch) {
			_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateFailed, "network_conflict")
			return
		}
		manager.logger.WarnWithFields("VNet network installation is required", err, map[string]any{
			"event": "vnet_installation_required",
		})
		_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateInstallationRequired, "device_unavailable")
		return
	}
	device := preparedDevice
	var userspaceTCP *vnet.UserspaceTCP
	if assignment.NetworkMode == string(config.VNetNetworkModeLoopback) {
		prefix, _ := netip.ParsePrefix(assignment.CIDR)
		var userspaceError error
		userspaceTCP, userspaceError = vnet.NewUserspaceTCP(
			manager.context, netip.MustParseAddr(assignment.ClientIP), prefix.Bits(), assignment.MTU,
			manager.sendUserspaceTCPPacket,
		)
		if userspaceError != nil {
			_ = device.Close()
			_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateFailed, "userspace_stack_unavailable")
			return
		}
	}
	manager.mutex.Lock()
	if ctx.Err() != nil || manager.assignment.PoolGeneration != assignment.PoolGeneration {
		manager.mutex.Unlock()
		if userspaceTCP != nil {
			_ = userspaceTCP.Close()
		}
		_ = device.Close()
		return
	}
	manager.device = device
	manager.userspaceTCP = userspaceTCP
	manager.waitGroup.Go(func() { manager.readDevice(device, assignment) })
	manager.mutex.Unlock()
	manager.logger.InfoWithFields("VNet network is ready", map[string]any{
		"event":          "vnet_network_ready",
		"interface_name": device.Name(),
		"virtual_ip":     assignment.ClientIP,
		"cidr":           assignment.CIDR,
	})
	_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateReady, "")
}

func (manager *clientVNetManager) activate(activation protocol.VNetActivate) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.device == nil || manager.assignment.State != protocol.VNetStateEnabled ||
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
	if assignment.State != protocol.VNetStateEnabled || manager.device == nil || !manager.activated {
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
	manager.mutex.Lock()
	if manager.assignment.PoolGeneration != assignment.PoolGeneration || !manager.activated {
		manager.mutex.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(manager.context)
	manager.poolCancel = cancel
	offers := make(map[uint8]protocol.OpenVNetChannel, len(manager.offers))
	for index, offer := range manager.offers {
		offers[index] = offer
	}
	manager.mutex.Unlock()
	channels := make([]transport.Stream, int(assignment.PacketChannels))
	channelWrites := make([]*vnet.PacketWriter, len(channels))
	for index := range channels {
		offer := offers[uint8(index)]
		stream, err := manager.transport.OpenDataStream(ctx)
		var stopCancel func() bool
		if err == nil {
			stopCancel = context.AfterFunc(ctx, func() { _ = stream.Close() })
			err = stream.SetDeadline(time.UnixMilli(offer.ExpiresAtUnixMS))
		}
		if err == nil {
			err = protocol.WriteControl(stream, protocol.MessageBindVNetChannel, protocol.BindVNetChannel{
				ClientID: manager.clientID, SessionID: manager.sessionID,
				TransportGeneration: assignment.TransportGeneration, VirtualIP: assignment.ClientIP,
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
		if stopCancel != nil {
			stopCancel()
		}
		if err != nil {
			cancel()
			if stream != nil {
				stream.Close()
			}
			closeVNetChannels(channels)
			_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateFailed, "channel_bind_failed")
			return
		}
		_ = stream.SetDeadline(time.Time{})
		channels[index] = stream
		channelWrites[index] = vnet.NewPacketWriter(ctx, stream, assignment.MTU, clientVNetChannelWriteTimeout)
	}
	manager.mutex.Lock()
	if manager.assignment.PoolGeneration != assignment.PoolGeneration || ctx.Err() != nil || !manager.activated || manager.device == nil {
		manager.mutex.Unlock()
		closeVNetChannels(channels)
		return
	}
	manager.channels = channels
	manager.channelWrites = channelWrites
	device := manager.device
	manager.mutex.Unlock()
	if err := manager.reportAssignmentStatus(assignment, protocol.VNetStateActive, ""); err != nil {
		manager.failPool(assignment.PoolGeneration, "status_report_failed")
		return
	}
	manager.logger.InfoWithFields("VNet is active", map[string]any{
		"event":          "vnet_active",
		"interface_name": device.Name(),
		"virtual_ip":     assignment.ClientIP,
		"channel_count":  len(channels),
	})
	for _, stream := range channels {
		channel := stream
		manager.waitGroup.Go(func() { manager.readChannel(device, assignment, channel) })
	}
}

func (manager *clientVNetManager) readDevice(
	device vnet.Device,
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
			manager.failPool(current.PoolGeneration, "device_read_failed")
			if !hadChannels && manager.context.Err() == nil {
				_ = manager.reportAssignmentStatus(current, protocol.VNetStateFailed, "device_read_failed")
			}
			_ = device.Close()
			if userspaceTCP != nil {
				_ = userspaceTCP.Close()
			}
			return
		}
		packet := append([]byte(nil), buffer[:length]...)
		flow, err := vnet.ParseIPv4(packet)
		if err != nil || flow.SourceIP.String() != assignment.ClientIP {
			continue
		}
		manager.mutex.Lock()
		if manager.device != device {
			manager.mutex.Unlock()
			return
		}
		userspaceTCP := manager.userspaceTCP
		manager.mutex.Unlock()
		if userspaceTCP != nil && !userspaceTCP.ObserveHostPacket(packet) {
			continue
		}
		_ = manager.sendUserspaceTCPPacket(packet)
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
		manager.mutex.Lock()
		if manager.assignment.PoolGeneration != assignment.PoolGeneration || manager.device != device || len(manager.channels) == 0 {
			manager.mutex.Unlock()
			return
		}
		userspaceTCP := manager.userspaceTCP
		manager.mutex.Unlock()
		if userspaceTCP != nil && userspaceTCP.Handle(packet) {
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

func (manager *clientVNetManager) sendUserspaceTCPPacket(packet []byte) error {
	flow, err := vnet.ParseIPv4(packet)
	if err != nil {
		return err
	}
	manager.mutex.Lock()
	assignment := manager.assignment
	// Published pool slices are immutable; replacement only swaps the slice headers.
	channelWrites := manager.channelWrites
	manager.mutex.Unlock()
	index, err := vnet.ChannelIndex(flow, assignment.PacketChannels)
	if err != nil || int(index) >= len(channelWrites) {
		return errors.New("VNet userspace stack pool is unavailable")
	}
	err = channelWrites[index].Send(packet)
	if err != nil {
		manager.failPool(assignment.PoolGeneration, "channel_write_failed")
	}
	return err
}

func (manager *clientVNetManager) failPool(generation uint64, code string) {
	manager.mutex.Lock()
	if manager.assignment.PoolGeneration != generation || len(manager.channels) == 0 {
		manager.mutex.Unlock()
		return
	}
	assignment := manager.assignment
	channels := manager.channels
	manager.channels = nil
	manager.channelWrites = nil
	manager.activated = false
	if manager.poolCancel != nil {
		manager.poolCancel()
	}
	manager.mutex.Unlock()
	closeVNetChannels(channels)
	_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateFailed, code)
}

func (manager *clientVNetManager) deactivate(deactivation protocol.VNetDeactivate) error {
	manager.mutex.Lock()
	if deactivation.PoolGeneration != 0 && manager.assignment.PoolGeneration != 0 &&
		deactivation.PoolGeneration != manager.assignment.PoolGeneration {
		manager.mutex.Unlock()
		return fmt.Errorf("%w: VNet pool generation mismatch", transport.ErrProtocol)
	}
	manager.mutex.Unlock()
	state := protocol.VNetStateRecovering
	if deactivation.Reason == protocol.VNetDeactivateDisabled ||
		deactivation.Reason == protocol.VNetDeactivateNodeRemoved {
		state = protocol.VNetStateDisabled
		manager.closeRuntime()
	} else {
		manager.closePoolRuntime()
	}
	return manager.reportStatus(state, string(deactivation.Reason))
}

func (manager *clientVNetManager) reportStatus(state protocol.VNetState, code string) error {
	manager.mutex.Lock()
	assignment := manager.assignment
	manager.mutex.Unlock()
	return manager.reportAssignmentStatus(assignment, state, code)
}

func (manager *clientVNetManager) reportAssignmentStatus(assignment protocol.VNetAssignment, state protocol.VNetState, code string) error {
	manager.mutex.Lock()
	current := manager.assignment.PoolGeneration == assignment.PoolGeneration
	if state == protocol.VNetStateReady || state == protocol.VNetStateActive {
		current = current && manager.device != nil
	}
	manager.mutex.Unlock()
	if !current {
		return nil
	}
	return manager.writer.Write(protocol.MessageVNetStatus, protocol.VNetStatus{
		State: state, PoolGeneration: assignment.PoolGeneration,
		ConfigGeneration: assignment.ConfigGeneration, Code: code,
	})
}

func (manager *clientVNetManager) closeRuntime() {
	manager.mutex.Lock()
	if manager.prepareCancel != nil {
		manager.prepareCancel()
	}
	manager.mutex.Unlock()
	manager.closePoolRuntime()
	manager.mutex.Lock()
	device := manager.device
	manager.device = nil
	userspaceTCP := manager.userspaceTCP
	manager.userspaceTCP = nil
	manager.mutex.Unlock()
	if userspaceTCP != nil {
		_ = userspaceTCP.Close()
	}
	if device != nil {
		device.Close()
	}
}

func (manager *clientVNetManager) closePoolRuntime() {
	manager.mutex.Lock()
	if manager.poolCancel != nil {
		manager.poolCancel()
	}
	channels := manager.channels
	manager.channels = nil
	manager.channelWrites = nil
	manager.activated = false
	manager.mutex.Unlock()
	closeVNetChannels(channels)
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
	if assignment.NetworkMode != string(config.VNetNetworkModeTUN) &&
		assignment.NetworkMode != string(config.VNetNetworkModeLoopback) {
		return errors.New("invalid VNet network mode")
	}
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
	if assignment.TransportGeneration == 0 {
		return errors.New("invalid VNet transport generation")
	}
	switch assignment.State {
	case protocol.VNetStateDisabled, protocol.VNetStateEnabled,
		protocol.VNetStateInstallationRequired, protocol.VNetStateFailed:
		return nil
	default:
		return errors.New("invalid VNet assignment state")
	}
}
