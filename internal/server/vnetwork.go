package server

import (
	"context"
	"errors"
	"fmt"
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
	vnetMTU                 = 1280
	vnetPoolTicketLifetime  = 10 * time.Second
	vnetMaximumTrackedFlows = 65536
)

type serverVNetSession struct {
	sessionID      string
	generation     transport.Generation
	authentication authentication.Context
	writer         *control.Writer
	poolGeneration uint64
}

type serverVNetRuntime struct {
	context          context.Context
	cancel           context.CancelFunc
	logger           *logging.Logger
	mutex            sync.RWMutex
	configuration    config.VirtualNetworkConfig
	sessions         map[string]serverVNetSession
	router           *vnet.Router
	broker           *vnet.PoolBroker
	device           vnet.Device
	deviceWrite      sync.Mutex
	poolGeneration   atomic.Uint64
	configGeneration atomic.Uint64
	waitGroup        sync.WaitGroup
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
	}
	runtime.configGeneration.Store(1)
	if device != nil && router != nil {
		runtime.waitGroup.Go(func() { runtime.readDevice(device) })
	}
	runtime.waitGroup.Go(runtime.reconcileDevice)
	return runtime
}

func (runtime *serverVNetRuntime) attach(
	clientID string,
	sessionID string,
	generation transport.Generation,
	authenticationContext authentication.Context,
	writer *control.Writer,
) {
	runtime.mutex.Lock()
	runtime.sessions[clientID] = serverVNetSession{
		sessionID: sessionID, generation: generation,
		authentication: authenticationContext, writer: writer,
	}
	runtime.mutex.Unlock()
}

func (runtime *serverVNetRuntime) assign(clientID string, sessionID string) error {
	runtime.mutex.RLock()
	session, exists := runtime.sessions[clientID]
	configuration := runtime.configuration
	deviceReady := runtime.device != nil
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
			state = protocol.VNetStateActive
		}
	}
	poolGeneration := runtime.poolGeneration.Add(1)
	runtime.mutex.Lock()
	current := runtime.sessions[clientID]
	if current.sessionID != sessionID {
		runtime.mutex.Unlock()
		return errors.New("VNet session is no longer current")
	}
	current.poolGeneration = poolGeneration
	runtime.sessions[clientID] = current
	runtime.mutex.Unlock()
	assignment := protocol.VNetAssignment{
		CIDR: configuration.CIDR, ClientIP: node.IP, ServerIP: configuration.ServerIP,
		MTU: vnetMTU, PacketChannels: uint8(configuration.PacketChannels),
		PoolGeneration: poolGeneration, ConfigGeneration: runtime.configGeneration.Load(), State: state,
	}
	if err := session.writer.Write(protocol.MessageVNetAssignment, assignment); err != nil {
		return err
	}
	if state != protocol.VNetStateActive {
		return nil
	}
	if err := session.writer.Write(protocol.MessageVNetActivate, protocol.VNetActivate{
		PoolGeneration: poolGeneration, ConfigGeneration: runtime.configGeneration.Load(),
	}); err != nil {
		return err
	}
	offers, err := runtime.broker.Prepare(vnet.PoolSpec{
		ClientID: clientID, SessionID: sessionID,
		TransportGeneration: uint64(session.generation), VirtualIP: node.IP,
		PoolGeneration: poolGeneration, ChannelCount: uint8(configuration.PacketChannels),
		MTU: vnetMTU, Authentication: session.authentication,
	}, vnetPoolTicketLifetime)
	if err != nil {
		return err
	}
	for _, offer := range offers {
		if err := session.writer.Write(protocol.MessageOpenVNetChannel, offer); err != nil {
			runtime.broker.Remove(clientID, sessionID)
			return err
		}
	}
	return nil
}

func (runtime *serverVNetRuntime) applyConfiguration(configuration config.VirtualNetworkConfig, generation uint64) {
	runtime.mutex.Lock()
	previous := runtime.configuration
	runtime.configuration = configuration
	device := runtime.device
	networkChanged := previous.CIDR != configuration.CIDR || previous.ServerIP != configuration.ServerIP
	if !configuration.Enabled || networkChanged {
		runtime.device = nil
	}
	sessions := make([]serverVNetSession, 0, len(runtime.sessions))
	clientIDs := make([]string, 0, len(runtime.sessions))
	for clientID, session := range runtime.sessions {
		clientIDs = append(clientIDs, clientID)
		sessions = append(sessions, session)
	}
	runtime.mutex.Unlock()
	if device != nil && (!configuration.Enabled || networkChanged) {
		_ = device.Close()
	}
	runtime.configGeneration.Store(generation)
	if runtime.router != nil {
		_ = runtime.router.ApplyPolicy(configuration)
	}
	if configuration.Enabled {
		runtime.activateInstalledDevice(configuration)
	}
	for index, session := range sessions {
		clientID := clientIDs[index]
		oldNode, oldExists := config.VNetNode(previous, clientID)
		newNode, newExists := config.VNetNode(configuration, clientID)
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
		if newExists {
			_ = runtime.assign(clientID, session.sessionID)
		}
	}
}

func (runtime *serverVNetRuntime) activateInstalledDevice(configuration config.VirtualNetworkConfig) bool {
	runtime.mutex.RLock()
	ready := runtime.device != nil
	runtime.mutex.RUnlock()
	if ready {
		return false
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
	runtime.device = device
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
		if configuration.Enabled && runtime.activateInstalledDevice(configuration) {
			for index, session := range sessions {
				_ = runtime.assign(clientIDs[index], session.sessionID)
			}
			delay = time.Second
			continue
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
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
					return runtime.routeClientPacket(binding.ClientID, packet)
				})
				if err != nil && runtime.context.Err() == nil {
					runtime.logger.WarnWithFields("VNet channel pool stopped", err, map[string]any{
						"client_id": binding.ClientID, "event": "vnet_pool_stopped",
					})
				}
				runtime.broker.Remove(binding.ClientID, binding.SessionID)
				if runtime.context.Err() == nil && runtime.poolIsCurrent(
					binding.ClientID, binding.SessionID, binding.PoolGeneration,
				) {
					if err := runtime.assign(binding.ClientID, binding.SessionID); err != nil {
						runtime.logger.WarnWithFields("failed to replace VNet channel pool", err, map[string]any{
							"client_id": binding.ClientID, "event": "vnet_pool_replace_failed",
						})
					}
				}
			})
		},
	)
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
	return runtime.dispatch(destination, packet)
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
			if runtime.device == device {
				runtime.device = nil
			}
			runtime.mutex.Unlock()
			_ = device.Close()
			return
		}
		packet := append([]byte(nil), buffer[:length]...)
		destination, err := runtime.router.RouteServerPacket(packet, time.Now())
		if err == nil {
			_ = runtime.dispatch(destination, packet)
		}
	}
}

func (runtime *serverVNetRuntime) dispatch(destination vnet.Destination, packet []byte) error {
	if destination.Kind == vnet.DestinationServer {
		runtime.deviceWrite.Lock()
		defer runtime.deviceWrite.Unlock()
		if runtime.device == nil {
			return vnet.ErrTargetUnavailable
		}
		written, err := runtime.device.WritePacket(packet)
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
	}
	runtime.mutex.Unlock()
	runtime.broker.Remove(clientID, sessionID)
}

func (runtime *serverVNetRuntime) Close() {
	runtime.cancel()
	runtime.broker.Close()
	if runtime.device != nil {
		_ = runtime.device.Close()
	}
	runtime.waitGroup.Wait()
}

func (runtime *serverVNetRuntime) String() string {
	return fmt.Sprintf("VNet(%s)", runtime.configuration.CIDR)
}
