package client

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
	"github.com/acexy/portway/internal/vnet"
	"github.com/acexy/portway/internal/vnet/peer"
	"github.com/acexy/portway/internal/vnet/system"
	"github.com/acexy/portway/internal/vnet/userspace"
)

const clientVNetChannelWriteTimeout = 5 * time.Second

type vnetPoolFailure string

const (
	vnetFailureChannelWriteFailed  vnetPoolFailure = "channel_write_failed"
	vnetFailureChannelWriteTimeout vnetPoolFailure = "channel_write_timeout"
	vnetFailureStatusReportFailed  vnetPoolFailure = "status_report_failed"
	vnetFailureDeviceReadFailed    vnetPoolFailure = "device_read_failed"
	vnetFailureChannelReadFailed   vnetPoolFailure = "channel_read_failed"
	vnetFailureDeviceWriteFailed   vnetPoolFailure = "device_write_failed"
)

// clientVNetChannel keeps each stream and its writer in one immutable pool entry.
type clientVNetChannel struct {
	stream transport.Stream
	writer *vnet.PacketWriter
}

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
	device          system.Device
	migratingDevice system.Device
	userspaceTCP    *userspace.UserspaceTCP
	peerEndpoint    *peer.PeerEndpoint
	peerRuntime     *clientVNetPeerRuntime
	offers          map[uint8]protocol.OpenVNetChannel
	activated       bool
	channels        []clientVNetChannel
	waitGroup       sync.WaitGroup
	deviceWrite     sync.Mutex
	prepareMutex    sync.Mutex
	prepareCancel   context.CancelFunc
	poolCancel      context.CancelFunc
	prepareNetwork  func(context.Context, system.NetworkSpec) (system.Device, error)
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
	serverAddress string,
) *clientVNetManager {
	ctx, cancel := context.WithCancel(parent)
	sessionContext, sessionCancel := context.WithCancel(ctx)
	manager := &clientVNetManager{
		context:        ctx,
		cancel:         cancel,
		logger:         logger.WithComponent("vnet"),
		clientID:       clientID,
		sessionID:      sessionID,
		writer:         writer,
		transport:      transportSession,
		sessionContext: sessionContext,
		sessionCancel:  sessionCancel,
		serverAddress:  serverAddress,
		offers:         make(map[uint8]protocol.OpenVNetChannel),
		prepareNetwork: system.PrepareNetworkContext,
		failures:       make(chan error, 1),
		exitOnConflict: runtime.GOOS == "windows",
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
	channels := manager.detachPoolChannelsLocked()
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
	channels := manager.detachPoolChannelsLocked()
	if !preserveDevice {
		manager.device = nil
		manager.userspaceTCP = nil
		if device != nil && system.NetworkMigrationSupported(device) {
			manager.migratingDevice = device
		}
	}
	var peerEndpoint *peer.PeerEndpoint
	if !preservePeer {
		peerEndpoint = manager.peerEndpoint
		manager.peerEndpoint = nil
	}
	manager.assignment = assignment
	manager.offers = make(map[uint8]protocol.OpenVNetChannel)
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
			system.NetworkMigrationSupported(device) {
			if userspaceTCP != nil {
				_ = userspaceTCP.Close()
				userspaceTCP = nil
			}
			migrationError := system.MigrateNetworkContext(
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

func (manager *clientVNetManager) failPool(generation uint64, code vnetPoolFailure) {
	manager.mutex.Lock()
	if manager.assignment.PoolGeneration != generation || len(manager.channels) == 0 {
		manager.mutex.Unlock()
		return
	}
	manager.poolFailures++
	if code == vnetFailureChannelWriteTimeout {
		manager.writeTimeouts++
	}
	if manager.recoveryStarted.IsZero() {
		manager.recoveryStarted = time.Now()
	}
	assignment := manager.assignment
	channels := manager.detachPoolChannelsLocked()
	if manager.poolCancel != nil {
		manager.poolCancel()
	}
	manager.mutex.Unlock()
	closeVNetChannels(channels)
	_ = manager.reportAssignmentStatus(assignment, protocol.VNetStateFailed, string(code))
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
		if err := device.Close(); err != nil {
			manager.logger.Warn("failed to finish VNet device cleanup", err)
		}
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
	channels := manager.detachPoolChannelsLocked()
	manager.mutex.Unlock()
	closeVNetChannels(channels)
}

func (manager *clientVNetManager) close() {
	manager.cancel()
	manager.detachSession()
	manager.closeRuntime()
	manager.waitGroup.Wait()
}

// detachPoolChannelsLocked transfers stream cleanup to the caller. The caller must
// hold manager.mutex and close the detached channels after releasing it.
func (manager *clientVNetManager) detachPoolChannelsLocked() []clientVNetChannel {
	channels := manager.channels
	manager.channels = nil
	manager.activated = false
	return channels
}

func closeVNetChannels(channels []clientVNetChannel) {
	for _, channel := range channels {
		if channel.stream != nil {
			channel.stream.Close()
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
