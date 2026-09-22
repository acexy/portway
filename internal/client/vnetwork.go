package client

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
	"github.com/acexy/portway/internal/vnet"
)

const clientVNetChannelWriteTimeout = 5 * time.Second

type clientVNetManager struct {
	context         context.Context
	cancel          context.CancelFunc
	logger          *logging.Logger
	clientID        string
	sessionID       string
	writer          *control.Writer
	transport       transport.ClientSession
	sessionContext  context.Context
	sessionCancel   context.CancelFunc
	serverAddress   string
	mutex           sync.Mutex
	assignment      protocol.VNetAssignment
	device          vnet.Device
	migratingDevice vnet.Device
	userspaceTCP    *vnet.UserspaceTCP
	peerEndpoint    *vnet.PeerEndpoint
	peerRuntime     *clientVNetPeerRuntime
	offers          map[uint8]protocol.OpenVNetChannel
	activated       bool
	channels        []transport.Stream
	channelWrites   []*vnet.PacketWriter
	waitGroup       sync.WaitGroup
	deviceWrite     sync.Mutex
	prepareMutex    sync.Mutex
	prepareCancel   context.CancelFunc
	poolCancel      context.CancelFunc
	prepareNetwork  func(context.Context, vnet.NetworkSpec) (vnet.Device, error)
	failures        chan error
	exitOnConflict  bool
	poolFailures    uint64
	writeTimeouts   uint64
	recoveries      uint64
	recoveryStarted time.Time
	lastRecovery    time.Duration
}

func newClientVNetManager(
	parent context.Context,
	logger *logging.Logger,
	clientID string,
	sessionID string,
	writer *control.Writer,
	transportSession transport.ClientSession,
	serverAddresses ...string,
) *clientVNetManager {
	ctx, cancel := context.WithCancel(parent)
	sessionContext, sessionCancel := context.WithCancel(ctx)
	manager := &clientVNetManager{
		context: ctx, cancel: cancel, logger: logger.WithComponent("vnet"),
		clientID: clientID, sessionID: sessionID, writer: writer, transport: transportSession,
		sessionContext: sessionContext, sessionCancel: sessionCancel,
		offers: make(map[uint8]protocol.OpenVNetChannel), prepareNetwork: vnet.PrepareNetworkContext,
		failures: make(chan error, 1), exitOnConflict: runtime.GOOS == "windows",
	}
	if len(serverAddresses) != 0 {
		manager.serverAddress = serverAddresses[0]
	}
	manager.waitGroup.Go(manager.reportStatistics)
	return manager
}

func (s *Service) attachVNetManager(
	ctx context.Context,
	logger *logging.Logger,
	clientID string,
	sessionID string,
	writer *control.Writer,
	transportSession transport.ClientSession,
	serverAddress string,
) *clientVNetManager {
	s.vnetMutex.Lock()
	defer s.vnetMutex.Unlock()
	if s.vnetManager == nil {
		s.vnetManager = newClientVNetManager(
			ctx, logger, clientID, sessionID, writer, transportSession, serverAddress,
		)
		s.vnetManager.peerRuntime = &s.vnetPeerRuntime
		return s.vnetManager
	}
	s.vnetManager.bindSession(clientID, sessionID, writer, transportSession, serverAddress)
	return s.vnetManager
}

func (s *Service) closeVNetManager() {
	s.vnetMutex.Lock()
	manager := s.vnetManager
	s.vnetManager = nil
	s.vnetMutex.Unlock()
	if manager != nil {
		manager.close()
	}
}

func (manager *clientVNetManager) bindSession(
	clientID string,
	sessionID string,
	writer *control.Writer,
	transportSession transport.ClientSession,
	serverAddress string,
) {
	manager.detachSession()
	sessionContext, sessionCancel := context.WithCancel(manager.context)
	manager.mutex.Lock()
	manager.clientID = clientID
	manager.sessionID = sessionID
	manager.writer = writer
	manager.transport = transportSession
	manager.sessionContext = sessionContext
	manager.sessionCancel = sessionCancel
	manager.serverAddress = serverAddress
	manager.offers = make(map[uint8]protocol.OpenVNetChannel)
	manager.mutex.Unlock()
}

// detachSession releases control-session authority while preserving the process-owned VNet device.
func (manager *clientVNetManager) detachSession() {
	manager.mutex.Lock()
	if manager.prepareCancel != nil {
		manager.prepareCancel()
		manager.prepareCancel = nil
	}
	if manager.poolCancel != nil {
		manager.poolCancel()
		manager.poolCancel = nil
	}
	if manager.sessionCancel != nil {
		manager.sessionCancel()
		manager.sessionCancel = nil
	}
	channels := manager.channels
	manager.channels = nil
	manager.channelWrites = nil
	manager.activated = false
	peerEndpoint := manager.peerEndpoint
	manager.peerEndpoint = nil
	manager.writer = nil
	manager.transport = nil
	manager.offers = make(map[uint8]protocol.OpenVNetChannel)
	manager.mutex.Unlock()
	closeVNetChannels(channels)
	if peerEndpoint != nil {
		_ = peerEndpoint.Close()
	}
}

func (manager *clientVNetManager) applyAssignment(assignment protocol.VNetAssignment) error {
	if err := validateVNetAssignment(assignment, manager.clientID); err != nil {
		return fmt.Errorf("%w: %v", transport.ErrProtocol, err)
	}
	if assignment.State == protocol.VNetStateEnabled && assignment.PeerRegistrationTicket != "" {
		if err := manager.preparePeerEndpoint(assignment); err != nil {
			manager.logger.WarnWithFields("VNet P2P is unavailable; relay remains active", err, map[string]any{
				"event": "vnet_p2p_bind_failed",
			})
		}
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
	preservePeer := manager.peerEndpoint != nil && assignment.State == protocol.VNetStateEnabled && assignment.PeerRegistrationTicket != ""
	channels := manager.channels
	manager.channels = nil
	manager.channelWrites = nil
	if !preserveDevice {
		manager.device = nil
		manager.userspaceTCP = nil
		if device != nil && vnet.NetworkMigrationSupported(device) {
			manager.migratingDevice = device
		}
	}
	var peerEndpoint *vnet.PeerEndpoint
	if !preservePeer {
		peerEndpoint = manager.peerEndpoint
		manager.peerEndpoint = nil
	}
	manager.assignment = assignment
	manager.offers = make(map[uint8]protocol.OpenVNetChannel)
	manager.activated = false
	manager.mutex.Unlock()
	closeVNetChannels(channels)
	if peerEndpoint != nil {
		_ = peerEndpoint.Close()
	}
	if !preservePeer && manager.peerRuntime != nil && (assignment.State != protocol.VNetStateEnabled || assignment.PeerRegistrationTicket == "") {
		manager.peerRuntime.close()
	}
	if preserveDevice {
		return manager.reportAssignmentStatus(assignment, protocol.VNetStateReady, "")
	}
	manager.mutex.Lock()
	sessionContext := manager.sessionContext
	if sessionContext == nil && manager.writer != nil {
		sessionContext = manager.context
	}
	manager.mutex.Unlock()
	if sessionContext == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(sessionContext)
	manager.mutex.Lock()
	manager.prepareCancel = cancel
	manager.mutex.Unlock()
	manager.waitGroup.Go(func() {
		manager.prepareMutex.Lock()
		defer manager.prepareMutex.Unlock()
		if device != nil && previous.State == protocol.VNetStateEnabled &&
			assignment.State == protocol.VNetStateEnabled && previous.NetworkMode == assignment.NetworkMode &&
			vnet.NetworkMigrationSupported(device) {
			if userspaceTCP != nil {
				_ = userspaceTCP.Close()
				userspaceTCP = nil
			}
			migrationError := vnet.MigrateNetworkContext(
				ctx,
				device,
				clientNetworkSpec(previous),
				clientNetworkSpec(assignment),
			)
			if migrationError == nil {
				manager.activatePreparedDevice(ctx, assignment, device, false)
				return
			}
			manager.logger.Warn("failed to migrate VNet network; recreating the device", migrationError)
		}
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

func (manager *clientVNetManager) preparePeerEndpoint(assignment protocol.VNetAssignment) error {
	manager.mutex.Lock()
	existing := manager.peerEndpoint
	previous := manager.assignment
	var stale *vnet.PeerEndpoint
	if existing != nil && (previous.ClientIP != assignment.ClientIP || previous.MTU != assignment.MTU) {
		stale = existing
		manager.peerEndpoint = nil
		existing = nil
	}
	manager.mutex.Unlock()
	if stale != nil {
		_ = stale.Close()
	}
	if existing == nil {
		bindAddress, err := vnet.PeerUDPAddress(manager.serverAddress, true)
		if err != nil {
			return err
		}
		newEndpoint := vnet.NewPeerEndpoint
		if manager.peerRuntime != nil {
			newEndpoint = manager.peerRuntime.newEndpoint
		}
		manager.mutex.Lock()
		sessionContext, sessionID := manager.sessionContext, manager.sessionID
		if sessionContext == nil && manager.writer != nil {
			sessionContext = manager.context
		}
		manager.mutex.Unlock()
		if sessionContext == nil {
			return errors.New("VNet control session is unavailable")
		}
		endpoint, err := newEndpoint(
			sessionContext, bindAddress, manager.clientID, sessionID,
			assignment.ClientIP, assignment.MTU,
			func(status protocol.VNetPeerStatus) error {
				return manager.writePeerControl(protocol.MessageVNetPeerStatus, status)
			},
			manager.deliverPeerPacket,
		)
		if err != nil {
			return err
		}
		endpoint.SetFlowOpener(func(generation uint64, peerClientID string, flow vnet.Flow) error {
			return manager.writePeerControl(protocol.MessageVNetPeerFlowOpen, protocol.VNetPeerFlowOpen{
				PeerGeneration: generation, PeerClientID: peerClientID, Protocol: flow.Protocol,
				SourceIP: flow.SourceIP.String(), SourcePort: flow.SourcePort,
				DestinationIP: flow.DestinationIP.String(), DestinationPort: flow.DestinationPort,
				TCPFlags: flow.TCPFlags,
			})
		})
		manager.mutex.Lock()
		if manager.peerEndpoint == nil {
			manager.peerEndpoint = endpoint
			existing = endpoint
		} else {
			existing = manager.peerEndpoint
		}
		manager.mutex.Unlock()
		if existing != endpoint {
			_ = endpoint.Close()
		}
	}
	serverAddress, err := vnet.PeerUDPAddress(manager.serverAddress, false)
	if err != nil {
		return err
	}
	if err := existing.Register(serverAddress, assignment.PeerRegistrationTicket); err != nil {
		manager.logger.WarnWithFields("VNet P2P registration could not be sent; relay remains active", err, map[string]any{
			"event": "vnet_p2p_registration_failed",
		})
	}
	return nil
}

func (manager *clientVNetManager) peerOffer(offer protocol.VNetPeerOffer) error {
	manager.mutex.Lock()
	endpoint := manager.peerEndpoint
	manager.mutex.Unlock()
	if endpoint == nil {
		return manager.writePeerControl(protocol.MessageVNetPeerStatus, protocol.VNetPeerStatus{
			PeerGeneration: offer.PeerGeneration, PeerClientID: offer.PeerClientID,
			State: protocol.VNetPeerStateFailed, Code: "peer_unavailable",
		})
	}
	if err := endpoint.ApplyOffer(offer); err != nil {
		return manager.writePeerControl(protocol.MessageVNetPeerStatus, protocol.VNetPeerStatus{
			PeerGeneration: offer.PeerGeneration, PeerClientID: offer.PeerClientID,
			State: protocol.VNetPeerStateFailed, Code: "offer_rejected",
		})
	}
	return nil
}

func (manager *clientVNetManager) peerActivate(activation protocol.VNetPeerActivate) error {
	manager.mutex.Lock()
	endpoint := manager.peerEndpoint
	manager.mutex.Unlock()
	if endpoint == nil {
		return nil
	}
	if err := endpoint.Activate(activation); err != nil {
		return manager.writePeerControl(protocol.MessageVNetPeerStatus, protocol.VNetPeerStatus{
			PeerGeneration: activation.PeerGeneration, PeerClientID: activation.PeerClientID,
			State: protocol.VNetPeerStateFailed, Code: "activation_unavailable",
		})
	}
	return nil
}

func (manager *clientVNetManager) peerRevoke(revocation protocol.VNetPeerRevoke) {
	manager.mutex.Lock()
	endpoint := manager.peerEndpoint
	manager.mutex.Unlock()
	if endpoint != nil {
		endpoint.Revoke(revocation)
	}
}

func (manager *clientVNetManager) prepareDevice(ctx context.Context, assignment protocol.VNetAssignment) {
	preparedDevice, err := manager.prepareNetwork(ctx, clientNetworkSpec(assignment))
	if ctx.Err() != nil {
		if preparedDevice != nil {
			_ = preparedDevice.Close()
		}
		return
	}
	if err != nil {
		if errors.Is(err, vnet.ErrForeignResource) || errors.Is(err, vnet.ErrStateMismatch) {
			_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateFailed, "network_conflict")
			if manager.exitOnConflict {
				manager.logger.WarnWithFields(
					"VNet network conflict requires operator action; client is exiting. Stop other Portway processes, run 'portway vnetwork uninstall' as administrator, resolve any address or route overlap with the assigned VNet CIDR, then restart the client",
					err,
					map[string]any{
						"event":     "vnet_network_conflict",
						"vnet_cidr": assignment.CIDR,
					},
				)
				select {
				case manager.failures <- transport.Permanent(fmt.Errorf("Windows VNet network conflict: %w", err)):
				default:
				}
			}
			return
		}
		manager.logger.WarnWithFields("VNet network installation is required", err, map[string]any{
			"event": "vnet_installation_required",
		})
		_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateInstallationRequired, "device_unavailable")
		return
	}
	manager.activatePreparedDevice(ctx, assignment, preparedDevice, true)
}

func clientNetworkSpec(assignment protocol.VNetAssignment) vnet.NetworkSpec {
	return vnet.NetworkSpec{
		Role: vnet.NetworkRoleClient, CIDR: assignment.CIDR, LocalIP: assignment.ClientIP,
		ServerIP: assignment.ServerIP, MTU: assignment.MTU, OwnerUID: -1,
	}
}

func (manager *clientVNetManager) activatePreparedDevice(
	ctx context.Context,
	assignment protocol.VNetAssignment,
	device vnet.Device,
	startReader bool,
) {
	var userspaceTCP *vnet.UserspaceTCP
	if assignment.NetworkMode == protocol.VNetNetworkModeLoopback {
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
	manager.migratingDevice = nil
	manager.userspaceTCP = userspaceTCP
	if startReader {
		manager.waitGroup.Go(func() { manager.readDevice(device, assignment) })
	}
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
	sessionContext := manager.sessionContext
	if sessionContext == nil && manager.writer != nil {
		sessionContext = manager.context
	}
	if manager.assignment.PoolGeneration != assignment.PoolGeneration || !manager.activated ||
		sessionContext == nil || manager.transport == nil {
		manager.mutex.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(sessionContext)
	manager.poolCancel = cancel
	transportSession := manager.transport
	sessionID := manager.sessionID
	offers := make(map[uint8]protocol.OpenVNetChannel, len(manager.offers))
	for index, offer := range manager.offers {
		offers[index] = offer
	}
	manager.mutex.Unlock()
	channels := make([]transport.Stream, int(assignment.PacketChannels))
	channelWrites := make([]*vnet.PacketWriter, len(channels))
	for index := range channels {
		offer := offers[uint8(index)]
		stream, err := transportSession.OpenDataStream(ctx)
		var stopCancel func() bool
		if err == nil {
			stopCancel = context.AfterFunc(ctx, func() { _ = stream.Close() })
			err = stream.SetDeadline(time.UnixMilli(offer.ExpiresAtUnixMS))
		}
		if err == nil {
			err = protocol.WriteControl(stream, protocol.MessageBindVNetChannel, protocol.BindVNetChannel{
				ClientID: manager.clientID, SessionID: sessionID,
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
	if !manager.recoveryStarted.IsZero() {
		manager.lastRecovery = time.Since(manager.recoveryStarted)
		manager.recoveries++
		manager.recoveryStarted = time.Time{}
	}
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
		flow, err := vnet.ParseIPv4(packet)
		if err != nil || flow.SourceIP.String() != current.ClientIP {
			continue
		}
		if userspaceTCP != nil && !userspaceTCP.ObserveHostPacket(packet) {
			continue
		}
		_ = manager.sendUserspaceTCPPacket(packet)
	}
}

func (manager *clientVNetManager) deliverPeerPacket(packet []byte) error {
	manager.mutex.Lock()
	device := manager.device
	userspaceTCP := manager.userspaceTCP
	manager.mutex.Unlock()
	if device == nil {
		return errors.New("VNet device is unavailable")
	}
	if userspaceTCP != nil && userspaceTCP.Handle(packet) {
		return nil
	}
	manager.deviceWrite.Lock()
	written, err := device.WritePacket(packet)
	manager.deviceWrite.Unlock()
	if err == nil && written != len(packet) {
		return errors.New("short VNet peer device write")
	}
	return err
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
	peerEndpoint := manager.peerEndpoint
	// Published pool slices are immutable; replacement only swaps the slice headers.
	channelWrites := manager.channelWrites
	manager.mutex.Unlock()
	if peerEndpoint != nil {
		if sent, sendError := peerEndpoint.Send(flow, packet, time.Now()); sent {
			return sendError
		}
		peerEndpoint.MarkRelay(flow, time.Now())
	}
	index, err := vnet.ChannelIndex(flow, assignment.PacketChannels)
	if err != nil || int(index) >= len(channelWrites) {
		return errors.New("VNet userspace stack pool is unavailable")
	}
	err = channelWrites[index].Send(packet)
	if err != nil {
		code := "channel_write_failed"
		if errors.Is(err, os.ErrDeadlineExceeded) {
			code = "channel_write_timeout"
		}
		manager.failPool(assignment.PoolGeneration, code)
	}
	return err
}

func (manager *clientVNetManager) failPool(generation uint64, code string) {
	manager.mutex.Lock()
	if manager.assignment.PoolGeneration != generation || len(manager.channels) == 0 {
		manager.mutex.Unlock()
		return
	}
	manager.poolFailures++
	if code == "channel_write_timeout" {
		manager.writeTimeouts++
	}
	if manager.recoveryStarted.IsZero() {
		manager.recoveryStarted = time.Now()
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
		if manager.peerRuntime != nil {
			manager.peerRuntime.close()
		}
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
	writer := manager.writer
	manager.mutex.Unlock()
	if !current || writer == nil {
		return nil
	}
	return writer.Write(protocol.MessageVNetStatus, protocol.VNetStatus{
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
	migratingDevice := manager.migratingDevice
	manager.migratingDevice = nil
	userspaceTCP := manager.userspaceTCP
	manager.userspaceTCP = nil
	peerEndpoint := manager.peerEndpoint
	manager.peerEndpoint = nil
	manager.mutex.Unlock()
	if userspaceTCP != nil {
		_ = userspaceTCP.Close()
	}
	if device != nil {
		device.Close()
	}
	if migratingDevice != nil && migratingDevice != device {
		_ = migratingDevice.Close()
	}
	if peerEndpoint != nil {
		_ = peerEndpoint.Close()
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
	manager.detachSession()
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
	if assignment.NetworkMode != protocol.VNetNetworkModeTUN &&
		assignment.NetworkMode != protocol.VNetNetworkModeLoopback {
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
		assignment.PacketChannels > protocol.VNetMaximumPacketChannels || assignment.PoolGeneration == 0 || assignment.ConfigGeneration == 0 {
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

// Peer control work must not indefinitely block device or datagram readers.
func (manager *clientVNetManager) writePeerControl(message protocol.MessageType, payload any) error {
	manager.mutex.Lock()
	writer := manager.writer
	manager.mutex.Unlock()
	if writer == nil {
		return errors.New("VNet control session is unavailable")
	}
	err := writer.WriteUntil(time.Now().Add(clientVNetChannelWriteTimeout), message, payload)
	if err != nil {
		_ = writer.Close()
	}
	return err
}

func (manager *clientVNetManager) reportStatistics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-manager.context.Done():
			return
		case <-ticker.C:
			manager.mutex.Lock()
			peer, userspace := manager.peerEndpoint, manager.userspaceTCP
			hasAssignment := manager.assignment.PoolGeneration != 0
			fields := map[string]any{"event": "vnet_statistics", "pool_failures": manager.poolFailures, "write_timeouts": manager.writeTimeouts, "recoveries": manager.recoveries, "last_recovery_ms": manager.lastRecovery.Milliseconds()}
			manager.mutex.Unlock()
			if peer == nil && userspace == nil && !hasAssignment {
				continue
			}
			if peer != nil {
				statistics := peer.Statistics()
				fields["flows"], fields["direct_peers"] = statistics.Active, statistics.ActivePeers
				fields["capacity_rejected"], fields["rate_rejected"] = statistics.CapacityRejected, statistics.RateRejected
				fields["direct_fallbacks"] = statistics.Fallbacks
			}
			if userspace != nil {
				local := userspace.Statistics()
				fields["userspace_flows"], fields["tcp_connections"], fields["udp_associations"] = local.Flows, local.TCPConnections, local.UDPAssociations
			}
			manager.logger.DebugWithFields("VNet resource statistics", fields)
		}
	}
}
