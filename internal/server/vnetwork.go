package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
	"github.com/acexy/portway/internal/vnet"
)

const (
	// vnetMTU leaves room for the QUIC Datagram and Portway peer frame on a
	// minimum-size QUIC path without relying on outer IP fragmentation.
	vnetMTU                 = 1150
	vnetPoolTicketLifetime  = 10 * time.Second
	vnetMaximumTrackedFlows = 65536
	vnetChannelWriteTimeout = 5 * time.Second
)

type serverVNetSession struct {
	sessionID              string
	generation             transport.Generation
	authentication         authentication.Context
	writer                 *control.Writer
	poolGeneration         uint64
	configGeneration       uint64
	channelsOffered        bool
	lifecycleMutex         *sync.Mutex
	peerRegistrationSecret []byte
	peerFingerprint        string
	peerCandidates         []protocol.VNetPeerCandidate
	peerAddress            string
	peerNegotiated         bool
}

type serverVNetRuntime struct {
	context           context.Context
	cancel            context.CancelFunc
	logger            *logging.Logger
	mutex             sync.RWMutex
	configuration     config.VirtualNetworkConfig
	sessions          map[string]serverVNetSession
	router            *vnet.Router
	broker            *vnet.PoolBroker
	device            vnet.Device
	userspaceTCP      *vnet.UserspaceTCP
	deviceWrite       sync.Mutex
	poolGeneration    atomic.Uint64
	configGeneration  atomic.Uint64
	preparingDevice   atomic.Bool
	prepareCancel     context.CancelFunc
	prepareNetwork    func(context.Context, vnet.NetworkSpec) (vnet.Device, error)
	waitGroup         sync.WaitGroup
	peerConnection    *net.UDPConn
	peerListenAddress string
	peerFatal         func(error)
	peerPairs         map[string]*serverVNetPeerPair
	peerSequence      atomic.Uint64
}

func newServerVNetRuntime(
	parent context.Context,
	logger *logging.Logger,
	configuration config.VirtualNetworkConfig,
	device vnet.Device,
) *serverVNetRuntime {
	ctx, cancel := context.WithCancel(parent)
	router, err := vnet.NewRouter(configuration, vnetMaximumTrackedFlows)
	if err != nil {
		logger.Error("failed to initialize VNet router", err)
	}
	runtime := &serverVNetRuntime{
		context: ctx, cancel: cancel, logger: logger,
		configuration: configuration, sessions: make(map[string]serverVNetSession),
		router: router, broker: vnet.NewPoolBroker(), device: device,
		peerPairs:      make(map[string]*serverVNetPeerPair),
		prepareNetwork: vnet.PrepareNetworkContext,
	}
	runtime.configGeneration.Store(1)
	if device != nil && router != nil {
		runtime.prepareUserspaceTCP(configuration)
		runtime.waitGroup.Go(func() { runtime.readDevice(device) })
	}
	runtime.waitGroup.Go(runtime.reconcileDevice)
	return runtime
}

func (runtime *serverVNetRuntime) prepareUserspaceTCP(configuration config.VirtualNetworkConfig) {
	runtime.mutex.Lock()
	defer runtime.mutex.Unlock()
	runtime.prepareUserspaceTCPLocked(configuration)
}

func (runtime *serverVNetRuntime) prepareUserspaceTCPLocked(configuration config.VirtualNetworkConfig) {
	if config.EffectiveVNetNetworkMode(configuration) != config.VNetNetworkModeLoopback ||
		runtime.userspaceTCP != nil {
		return
	}
	prefix, err := netip.ParsePrefix(configuration.CIDR)
	if err != nil {
		return
	}
	userspaceTCP, err := vnet.NewUserspaceTCP(
		runtime.context,
		netip.MustParseAddr(configuration.ServerIP),
		prefix.Bits(),
		vnetMTU,
		runtime.sendUserspaceTCPPacket,
	)
	if err != nil {
		runtime.logger.Error("failed to initialize VNet userspace TCP/IP stack", err)
		return
	}
	runtime.userspaceTCP = userspaceTCP
}

func (runtime *serverVNetRuntime) sendUserspaceTCPPacket(packet []byte) error {
	destination, err := runtime.router.RouteServerPacket(packet, time.Now())
	if err != nil {
		return err
	}
	return runtime.dispatch(destination, packet)
}

func (runtime *serverVNetRuntime) attach(
	clientID string,
	sessionID string,
	generation transport.Generation,
	authenticationContext authentication.Context,
	writer *control.Writer,
	peerNegotiatedValues ...bool,
) {
	peerNegotiated := len(peerNegotiatedValues) != 0 && peerNegotiatedValues[0]
	runtime.mutex.Lock()
	runtime.sessions[clientID] = serverVNetSession{
		sessionID: sessionID, generation: generation,
		authentication: authenticationContext, writer: writer, peerNegotiated: peerNegotiated,
	}
	runtime.mutex.Unlock()
}

// lockSession serializes generation transitions without blocking unrelated clients.
func (runtime *serverVNetRuntime) lockSession(clientID, sessionID string) func() {
	runtime.mutex.Lock()
	session, exists := runtime.sessions[clientID]
	if !exists || session.sessionID != sessionID {
		runtime.mutex.Unlock()
		return func() {}
	}
	if session.lifecycleMutex == nil {
		session.lifecycleMutex = &sync.Mutex{}
		runtime.sessions[clientID] = session
	}
	mutex := session.lifecycleMutex
	runtime.mutex.Unlock()
	mutex.Lock()
	return mutex.Unlock
}

func (runtime *serverVNetRuntime) assign(clientID string, sessionID string) error {
	unlock := runtime.lockSession(clientID, sessionID)
	defer unlock()
	return runtime.assignLocked(clientID, sessionID)
}

func (runtime *serverVNetRuntime) assignLocked(clientID string, sessionID string) error {
	runtime.mutex.RLock()
	session, exists := runtime.sessions[clientID]
	configuration := runtime.configuration
	configurationGeneration := runtime.configGeneration.Load()
	deviceReady := runtime.device != nil
	userspaceReady := runtime.userspaceTCP != nil
	runtime.mutex.RUnlock()
	if !exists || session.sessionID != sessionID {
		return errors.New("VNet session is no longer current")
	}
	node, configured := config.VNetNode(configuration, clientID)
	if !configured {
		return nil
	}
	state := protocol.VNetStateDisabled
	if configuration.Enabled {
		state = protocol.VNetStateInstallationRequired
		if deviceReady {
			state = protocol.VNetStateEnabled
			if config.EffectiveVNetNetworkMode(configuration) == config.VNetNetworkModeLoopback &&
				!userspaceReady {
				state = protocol.VNetStateFailed
			}
		}
	}
	poolGeneration := runtime.poolGeneration.Add(1)
	registrationSecret := make([]byte, 32)
	if _, err := rand.Read(registrationSecret); err != nil {
		return fmt.Errorf("generate VNet peer registration ticket: %w", err)
	}
	runtime.mutex.Lock()
	current := runtime.sessions[clientID]
	if current.sessionID != sessionID {
		runtime.mutex.Unlock()
		return errors.New("VNet session is no longer current")
	}
	current.poolGeneration = poolGeneration
	current.configGeneration = configurationGeneration
	current.channelsOffered = false
	if current.peerNegotiated && configuration.Enabled {
		current.peerRegistrationSecret = registrationSecret
	} else {
		current.peerRegistrationSecret = nil
	}
	current.peerFingerprint = ""
	current.peerCandidates = nil
	current.peerAddress = ""
	runtime.sessions[clientID] = current
	runtime.mutex.Unlock()
	assignment := protocol.VNetAssignment{
		NetworkMode: string(config.EffectiveVNetNetworkMode(configuration)),
		CIDR:        configuration.CIDR, ClientIP: node.IP, ServerIP: configuration.ServerIP,
		MTU: vnetMTU, PacketChannels: uint8(configuration.PacketChannels),
		TransportGeneration: uint64(session.generation),
		PoolGeneration:      poolGeneration, ConfigGeneration: current.configGeneration, State: state,
	}
	if len(current.peerRegistrationSecret) != 0 {
		assignment.PeerRegistrationTicket = base64.RawURLEncoding.EncodeToString(registrationSecret)
	}
	if err := session.writer.Write(protocol.MessageVNetAssignment, assignment); err != nil {
		return err
	}
	return nil
}

func (runtime *serverVNetRuntime) activate(clientID string, sessionID string, status protocol.VNetStatus) error {
	unlock := runtime.lockSession(clientID, sessionID)
	defer unlock()
	runtime.mutex.RLock()
	current := runtime.sessions[clientID]
	_, configured := config.VNetNode(runtime.configuration, clientID)
	enabled := runtime.configuration.Enabled
	runtime.mutex.RUnlock()
	if current.sessionID == sessionID && (!enabled || !configured || current.poolGeneration == 0 ||
		status.PoolGeneration < current.poolGeneration) {
		return nil
	}
	if status.State == protocol.VNetStateFailed {
		if status.Code == "network_conflict" || status.Code == "userspace_stack_unavailable" {
			return nil
		}
		return runtime.replaceFailedPoolLocked(clientID, sessionID, status)
	}
	if status.State != protocol.VNetStateReady {
		return nil
	}
	runtime.mutex.Lock()
	session, exists := runtime.sessions[clientID]
	configuration := runtime.configuration
	configurationGeneration := session.configGeneration
	if !exists || session.sessionID != sessionID || session.poolGeneration != status.PoolGeneration ||
		status.ConfigGeneration != configurationGeneration {
		runtime.mutex.Unlock()
		return errors.New("VNet readiness status does not match the current assignment")
	}
	if session.channelsOffered {
		runtime.mutex.Unlock()
		return nil
	}
	session.channelsOffered = true
	runtime.sessions[clientID] = session
	runtime.mutex.Unlock()
	node, configured := config.VNetNode(configuration, clientID)
	if !configuration.Enabled || !configured {
		runtime.resetOffered(clientID, sessionID, status.PoolGeneration)
		return errors.New("VNet readiness status targets a disabled assignment")
	}
	offers, err := runtime.broker.Prepare(vnet.PoolSpec{
		ClientID: clientID, SessionID: sessionID,
		TransportGeneration: uint64(session.generation), VirtualIP: node.IP,
		PoolGeneration: status.PoolGeneration, ChannelCount: uint8(configuration.PacketChannels),
		MTU: vnetMTU, WriteTimeout: vnetChannelWriteTimeout, Authentication: session.authentication,
	}, vnetPoolTicketLifetime)
	if err != nil {
		runtime.resetOffered(clientID, sessionID, status.PoolGeneration)
		return err
	}
	if err := session.writer.Write(protocol.MessageVNetActivate, protocol.VNetActivate{
		PoolGeneration: status.PoolGeneration, ConfigGeneration: configurationGeneration,
	}); err != nil {
		runtime.broker.Remove(clientID, sessionID)
		runtime.resetOffered(clientID, sessionID, status.PoolGeneration)
		return err
	}
	for _, offer := range offers {
		if err := session.writer.Write(protocol.MessageOpenVNetChannel, offer); err != nil {
			runtime.broker.Remove(clientID, sessionID)
			runtime.resetOffered(clientID, sessionID, status.PoolGeneration)
			return err
		}
	}
	return nil
}

func (runtime *serverVNetRuntime) replaceFailedPool(
	clientID string,
	sessionID string,
	status protocol.VNetStatus,
) error {
	unlock := runtime.lockSession(clientID, sessionID)
	defer unlock()
	return runtime.replaceFailedPoolLocked(clientID, sessionID, status)
}

func (runtime *serverVNetRuntime) replaceFailedPoolLocked(clientID, sessionID string, status protocol.VNetStatus) error {
	runtime.mutex.Lock()
	session, exists := runtime.sessions[clientID]
	if !exists || session.sessionID != sessionID || session.poolGeneration != status.PoolGeneration ||
		status.ConfigGeneration != session.configGeneration {
		runtime.mutex.Unlock()
		return errors.New("VNet failure status does not match the current assignment")
	}
	session.channelsOffered = false
	runtime.sessions[clientID] = session
	runtime.mutex.Unlock()
	runtime.broker.Remove(clientID, sessionID)
	return runtime.assignLocked(clientID, sessionID)
}

func (runtime *serverVNetRuntime) hasSession(clientID string) bool {
	runtime.mutex.RLock()
	defer runtime.mutex.RUnlock()
	_, exists := runtime.sessions[clientID]
	return exists
}

func (runtime *serverVNetRuntime) resetOffered(clientID string, sessionID string, generation uint64) {
	runtime.mutex.Lock()
	defer runtime.mutex.Unlock()
	session, exists := runtime.sessions[clientID]
	if exists && session.sessionID == sessionID && session.poolGeneration == generation {
		session.channelsOffered = false
		runtime.sessions[clientID] = session
	}
}

func (runtime *serverVNetRuntime) applyConfiguration(configuration config.VirtualNetworkConfig, generation uint64) {
	runtime.mutex.Lock()
	previous := runtime.configuration
	runtime.configuration = configuration
	runtime.configGeneration.Store(generation)
	device := runtime.device
	userspaceTCP := runtime.userspaceTCP
	networkChanged := previous.CIDR != configuration.CIDR || previous.ServerIP != configuration.ServerIP
	canMigrateDevice := configuration.Enabled && networkChanged && device != nil &&
		vnet.NetworkMigrationSupported(device)
	if !configuration.Enabled || networkChanged {
		if runtime.prepareCancel != nil {
			runtime.prepareCancel()
		}
		runtime.device = nil
		runtime.userspaceTCP = nil
	}
	if runtime.router != nil {
		for _, node := range previous.Nodes {
			replacement, exists := config.VNetNode(configuration, node.ClientID)
			if networkChanged || !exists || replacement.IP != node.IP {
				runtime.router.RemoveClient(node.ClientID)
			}
		}
	}
	sessions := make([]serverVNetSession, 0, len(runtime.sessions))
	clientIDs := make([]string, 0, len(runtime.sessions))
	for clientID, session := range runtime.sessions {
		clientIDs = append(clientIDs, clientID)
		sessions = append(sessions, session)
	}
	runtime.mutex.Unlock()
	if previous.Enabled && !configuration.Enabled {
		runtime.stopPeerCoordinator()
	}
	if !previous.Enabled && configuration.Enabled {
		if err := runtime.startPeerCoordinator(runtime.peerListenAddress); err != nil {
			runtime.logger.Warn("VNet P2P UDP port is unavailable; server is exiting", err)
			if runtime.peerFatal != nil {
				runtime.peerFatal(fmt.Errorf("start VNet P2P coordinator: %w", err))
			}
		}
	}
	runtime.revokeAllPeers("configuration_changed")
	if device != nil && (!configuration.Enabled || networkChanged) && !canMigrateDevice {
		_ = device.Close()
	}
	if userspaceTCP != nil && (!configuration.Enabled || networkChanged) {
		_ = userspaceTCP.Close()
	}
	if runtime.router != nil {
		_ = runtime.router.ApplyPolicy(configuration)
	}
	for index, session := range sessions {
		runtime.updateSessionConfiguration(clientIDs[index], session, previous, configuration, generation, networkChanged)
	}
	migrationStarted := false
	if configuration.Enabled && canMigrateDevice {
		migrationStarted = runtime.migrateRuntimeDevice(device, previous, configuration)
		if !migrationStarted {
			_ = device.Close()
		}
	}
	if configuration.Enabled && !runtime.deviceReady() && !migrationStarted {
		runtime.prepareRuntimeDevice(configuration)
	}
}

func serverNetworkSpec(configuration config.VirtualNetworkConfig) vnet.NetworkSpec {
	return vnet.NetworkSpec{
		Role: vnet.NetworkRoleServer, CIDR: configuration.CIDR,
		LocalIP: configuration.ServerIP, ServerIP: configuration.ServerIP,
		MTU: vnetMTU, OwnerUID: -1,
	}
}

func (runtime *serverVNetRuntime) migrateRuntimeDevice(
	device vnet.Device,
	previous, configuration config.VirtualNetworkConfig,
) bool {
	if !runtime.preparingDevice.CompareAndSwap(false, true) {
		return false
	}
	ctx, cancel := context.WithCancel(runtime.context)
	runtime.mutex.Lock()
	runtime.prepareCancel = cancel
	runtime.mutex.Unlock()
	runtime.waitGroup.Go(func() {
		startReader := false
		defer func() {
			cancel()
			runtime.preparingDevice.Store(false)
			runtime.mutex.RLock()
			latest := runtime.configuration
			retry := runtime.context.Err() == nil && latest.Enabled && runtime.device == nil
			runtime.mutex.RUnlock()
			if retry {
				runtime.prepareRuntimeDevice(latest)
			}
		}()
		err := vnet.MigrateNetworkContext(
			ctx,
			device,
			serverNetworkSpec(previous),
			serverNetworkSpec(configuration),
		)
		if err != nil {
			runtime.logger.Warn("failed to migrate VNet network; recreating the device", err)
			_ = device.Close()
			if ctx.Err() != nil {
				return
			}
			device, err = runtime.prepareNetwork(ctx, serverNetworkSpec(configuration))
			if err != nil {
				if ctx.Err() == nil {
					runtime.logger.Warn("VNet network installation did not activate the network", err)
				}
				return
			}
			startReader = true
		}
		runtime.mutex.Lock()
		if ctx.Err() != nil || runtime.device != nil || !runtime.configuration.Enabled ||
			runtime.configuration.CIDR != configuration.CIDR ||
			runtime.configuration.ServerIP != configuration.ServerIP {
			runtime.mutex.Unlock()
			_ = device.Close()
			return
		}
		runtime.device = device
		runtime.prepareUserspaceTCPLocked(configuration)
		sessions := make([]serverVNetSession, 0, len(runtime.sessions))
		clientIDs := make([]string, 0, len(runtime.sessions))
		for clientID, session := range runtime.sessions {
			clientIDs = append(clientIDs, clientID)
			sessions = append(sessions, session)
		}
		runtime.mutex.Unlock()
		if startReader {
			runtime.waitGroup.Go(func() { runtime.readDevice(device) })
		}
		for index, session := range sessions {
			_ = runtime.assign(clientIDs[index], session.sessionID)
		}
	})
	return true
}

func (runtime *serverVNetRuntime) updateSessionConfiguration(
	clientID string,
	session serverVNetSession,
	previous, configuration config.VirtualNetworkConfig,
	generation uint64,
	networkChanged bool,
) {
	unlock := runtime.lockSession(clientID, session.sessionID)
	defer unlock()
	oldNode, oldExists := config.VNetNode(previous, clientID)
	newNode, newExists := config.VNetNode(configuration, clientID)
	assignmentChanged := previous.Enabled != configuration.Enabled ||
		previous.PacketChannels != configuration.PacketChannels || networkChanged ||
		oldExists != newExists || oldNode.IP != newNode.IP
	if !assignmentChanged {
		return
	}
	reason := protocol.VNetDeactivatePolicyChanged
	if previous.Enabled && !configuration.Enabled {
		reason = protocol.VNetDeactivateDisabled
	} else if oldExists && !newExists {
		reason = protocol.VNetDeactivateNodeRemoved
	}
	if previous.Enabled || oldExists || oldNode.IP != newNode.IP {
		_ = session.writer.Write(protocol.MessageVNetDeactivate, protocol.VNetDeactivate{
			ConfigGeneration: generation, Reason: reason,
		})
	}
	runtime.mutex.Lock()
	current := runtime.sessions[clientID]
	if current.sessionID == session.sessionID {
		current.poolGeneration = 0
		runtime.sessions[clientID] = current
	}
	runtime.mutex.Unlock()
	runtime.broker.Remove(clientID, session.sessionID)
	if !newExists && runtime.router != nil {
		runtime.router.RemoveClient(clientID)
	}
	if newExists {
		_ = runtime.assignLocked(clientID, session.sessionID)
	}
}

func (runtime *serverVNetRuntime) prepareRuntimeDevice(configuration config.VirtualNetworkConfig) {
	if !runtime.preparingDevice.CompareAndSwap(false, true) {
		return
	}
	ctx, cancel := context.WithCancel(runtime.context)
	runtime.mutex.Lock()
	if runtime.device != nil || !runtime.configuration.Enabled ||
		runtime.configuration.CIDR != configuration.CIDR || runtime.configuration.ServerIP != configuration.ServerIP {
		runtime.mutex.Unlock()
		cancel()
		runtime.preparingDevice.Store(false)
		return
	}
	runtime.prepareCancel = cancel
	runtime.mutex.Unlock()
	runtime.waitGroup.Go(func() {
		defer func() {
			cancel()
			runtime.preparingDevice.Store(false)
			runtime.mutex.RLock()
			latest := runtime.configuration
			replaced := latest.CIDR != configuration.CIDR || latest.ServerIP != configuration.ServerIP
			retry := runtime.context.Err() == nil && latest.Enabled && runtime.device == nil && replaced
			runtime.mutex.RUnlock()
			if retry {
				runtime.prepareRuntimeDevice(latest)
			}
		}()
		device, err := runtime.prepareNetwork(ctx, serverNetworkSpec(configuration))
		if err != nil {
			if ctx.Err() == nil {
				runtime.logger.Warn("VNet network installation did not activate the network", err)
			}
			return
		}
		runtime.mutex.Lock()
		if ctx.Err() != nil || runtime.device != nil || !runtime.configuration.Enabled ||
			runtime.configuration.CIDR != configuration.CIDR ||
			runtime.configuration.ServerIP != configuration.ServerIP {
			runtime.mutex.Unlock()
			_ = device.Close()
			return
		}
		runtime.device = device
		runtime.prepareUserspaceTCPLocked(configuration)
		sessions := make([]serverVNetSession, 0, len(runtime.sessions))
		clientIDs := make([]string, 0, len(runtime.sessions))
		for clientID, session := range runtime.sessions {
			clientIDs = append(clientIDs, clientID)
			sessions = append(sessions, session)
		}
		runtime.mutex.Unlock()
		runtime.waitGroup.Go(func() { runtime.readDevice(device) })
		for index, session := range sessions {
			_ = runtime.assign(clientIDs[index], session.sessionID)
		}
	})
}

func (runtime *serverVNetRuntime) activateInstalledDevice(configuration config.VirtualNetworkConfig) bool {
	if runtime.preparingDevice.Load() {
		return false
	}
	runtime.mutex.RLock()
	ready := runtime.device != nil
	runtime.mutex.RUnlock()
	if ready {
		return true
	}
	status, err := vnet.InspectNetwork()
	if err != nil || !status.Installed || status.CIDR != configuration.CIDR || status.LocalIP != configuration.ServerIP {
		return false
	}
	device, err := vnet.OpenInstalledNetwork()
	if err != nil {
		return false
	}
	runtime.mutex.Lock()
	if runtime.device != nil || !runtime.configuration.Enabled {
		runtime.mutex.Unlock()
		_ = device.Close()
		return false
	}
	if runtime.configuration.CIDR != configuration.CIDR || runtime.configuration.ServerIP != configuration.ServerIP {
		runtime.mutex.Unlock()
		_ = device.Close()
		return false
	}
	runtime.device = device
	runtime.prepareUserspaceTCPLocked(configuration)
	runtime.mutex.Unlock()
	runtime.waitGroup.Go(func() { runtime.readDevice(device) })
	return true
}

func (runtime *serverVNetRuntime) reconcileDevice() {
	delay := time.Second
	for {
		timer := time.NewTimer(delay)
		select {
		case <-runtime.context.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		runtime.mutex.RLock()
		configuration := runtime.configuration
		sessions := make([]serverVNetSession, 0, len(runtime.sessions))
		clientIDs := make([]string, 0, len(runtime.sessions))
		for clientID, session := range runtime.sessions {
			clientIDs = append(clientIDs, clientID)
			sessions = append(sessions, session)
		}
		runtime.mutex.RUnlock()
		if configuration.Enabled && runtime.deviceReady() {
			delay = time.Second
			continue
		}
		if configuration.Enabled && runtime.activateInstalledDevice(configuration) {
			for index, session := range sessions {
				_ = runtime.assign(clientIDs[index], session.sessionID)
			}
			delay = time.Second
			continue
		}
		if configuration.Enabled && vnet.RuntimeReprepareSupported() {
			runtime.prepareRuntimeDevice(configuration)
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}

func (runtime *serverVNetRuntime) deviceReady() bool {
	runtime.mutex.RLock()
	defer runtime.mutex.RUnlock()
	return runtime.device != nil
}

func (runtime *serverVNetRuntime) bind(
	ctx context.Context,
	inbound transport.Inbound,
	binding protocol.BindVNetChannel,
	releaseAdmission func(),
) error {
	return runtime.broker.Bind(
		ctx, inbound.Stream, binding, inbound.Authentication,
		func() {
			releaseAdmission()
			_ = protocol.WriteControl(inbound.Stream, protocol.MessageVNetBindResult, protocol.VNetBindResult{
				PoolGeneration: binding.PoolGeneration,
				ChannelIndex:   binding.ChannelIndex,
				Status:         protocol.LinkStatusAccepted,
			})
			_ = inbound.Stream.SetDeadline(time.Time{})
		},
		func(pool *vnet.Pool) {
			runtime.waitGroup.Go(func() {
				err := pool.RunReaders(func(packet []byte) error {
					if !runtime.poolIsCurrent(binding.ClientID, binding.SessionID, binding.PoolGeneration) {
						return net.ErrClosed
					}
					return runtime.routeClientPacket(binding.ClientID, packet)
				})
				if err != nil && runtime.context.Err() == nil && !isExpectedVNetPoolStop(err) {
					runtime.logger.WarnWithFields("VNet channel pool stopped", err, map[string]any{
						"client_id": binding.ClientID, "event": "vnet_pool_stopped",
					})
				}
				unlock := runtime.lockSession(binding.ClientID, binding.SessionID)
				defer unlock()
				runtime.broker.RemoveGeneration(binding.ClientID, binding.SessionID, binding.PoolGeneration)
				if runtime.context.Err() == nil && runtime.poolIsCurrent(
					binding.ClientID, binding.SessionID, binding.PoolGeneration,
				) {
					if err := runtime.assignLocked(binding.ClientID, binding.SessionID); err != nil {
						runtime.logger.WarnWithFields("failed to replace VNet channel pool", err, map[string]any{
							"client_id": binding.ClientID, "event": "vnet_pool_replace_failed",
						})
					}
				}
			})
		},
	)
}

func isExpectedVNetPoolStop(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}

func (runtime *serverVNetRuntime) poolIsCurrent(clientID string, sessionID string, generation uint64) bool {
	runtime.mutex.RLock()
	defer runtime.mutex.RUnlock()
	session, exists := runtime.sessions[clientID]
	return exists && session.sessionID == sessionID && session.poolGeneration == generation
}

func (runtime *serverVNetRuntime) routeClientPacket(clientID string, packet []byte) error {
	destination, err := runtime.router.RouteClientPacket(clientID, packet, time.Now())
	if err != nil {
		if errors.Is(err, vnet.ErrInvalidPacket) {
			return err
		}
		return nil
	}
	if destination.Kind == vnet.DestinationClient && destination.ClientID != clientID {
		runtime.offerPeer(clientID, destination.ClientID)
	}
	// Destination failure must never tear down the source pool.
	_ = runtime.dispatch(destination, packet)
	return nil
}

func (runtime *serverVNetRuntime) readDevice(device vnet.Device) {
	buffer := make([]byte, vnetMTU)
	for {
		length, err := device.ReadPacket(buffer)
		if err != nil {
			if runtime.context.Err() == nil {
				runtime.logger.Error("VNet device reader stopped", err)
			}
			runtime.mutex.Lock()
			var userspaceTCP *vnet.UserspaceTCP
			if runtime.device == device {
				runtime.device = nil
				userspaceTCP = runtime.userspaceTCP
				runtime.userspaceTCP = nil
			}
			runtime.mutex.Unlock()
			if userspaceTCP != nil {
				_ = userspaceTCP.Close()
			}
			_ = device.Close()
			return
		}
		packet := append([]byte(nil), buffer[:length]...)
		runtime.mutex.RLock()
		userspaceTCP := runtime.userspaceTCP
		runtime.mutex.RUnlock()
		if userspaceTCP != nil && !userspaceTCP.ObserveHostPacket(packet) {
			continue
		}
		destination, err := runtime.router.RouteServerPacket(packet, time.Now())
		if err == nil {
			_ = runtime.dispatch(destination, packet)
		}
	}
}

func (runtime *serverVNetRuntime) dispatch(destination vnet.Destination, packet []byte) error {
	if destination.Kind == vnet.DestinationServer {
		runtime.mutex.RLock()
		userspaceTCP := runtime.userspaceTCP
		runtime.mutex.RUnlock()
		if userspaceTCP != nil && userspaceTCP.Handle(packet) {
			return nil
		}
		runtime.deviceWrite.Lock()
		defer runtime.deviceWrite.Unlock()
		runtime.mutex.RLock()
		device := runtime.device
		runtime.mutex.RUnlock()
		if device == nil {
			return vnet.ErrTargetUnavailable
		}
		written, err := device.WritePacket(packet)
		if err == nil && written != len(packet) {
			err = errors.New("short VNet device write")
		}
		return err
	}
	pool, exists := runtime.broker.Active(destination.ClientID)
	if !exists {
		return vnet.ErrTargetUnavailable
	}
	return pool.Send(packet, destination.ChannelIndex)
}

func (runtime *serverVNetRuntime) detach(clientID string, sessionID string) {
	runtime.mutex.Lock()
	session, exists := runtime.sessions[clientID]
	if exists && session.sessionID == sessionID {
		delete(runtime.sessions, clientID)
		if runtime.router != nil {
			runtime.router.RemoveClient(clientID)
		}
	}
	runtime.mutex.Unlock()
	runtime.revokeClientPeers(clientID, "session_closed")
	runtime.broker.Remove(clientID, sessionID)
}

func (runtime *serverVNetRuntime) Close() {
	runtime.cancel()
	runtime.stopPeerCoordinator()
	runtime.broker.Close()
	runtime.mutex.Lock()
	device := runtime.device
	runtime.device = nil
	userspaceTCP := runtime.userspaceTCP
	runtime.userspaceTCP = nil
	runtime.mutex.Unlock()
	if device != nil {
		_ = device.Close()
	}
	if userspaceTCP != nil {
		_ = userspaceTCP.Close()
	}
	runtime.waitGroup.Wait()
}

func (runtime *serverVNetRuntime) String() string {
	return fmt.Sprintf("VNet(%s)", runtime.configuration.CIDR)
}
