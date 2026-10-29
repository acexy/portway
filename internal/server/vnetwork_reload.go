package server

import (
	"sync"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/vnet/system"
)

func (s *Service) validateVNetConfigurationTransition(
	current config.VirtualNetworkConfig,
	candidate config.VirtualNetworkConfig,
) error {
	if config.EffectiveVNetNetworkMode(current) != config.EffectiveVNetNetworkMode(candidate) {
		return restartRequiredError{field: "virtual_network.network_mode"}
	}
	return nil
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
		system.NetworkMigrationSupported(device)
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
		// Publish the relay policy before any potentially blocking peer notices.
		_ = runtime.router.ApplyPolicy(configuration)
	}
	sessions := runtime.sessionSnapshotsLocked()
	for _, session := range sessions {
		if vnetAssignmentChanged(previous, configuration, session.clientID) {
			current := runtime.sessions[session.clientID]
			current.poolGeneration = 0
			current.channelsOffered = false
			runtime.sessions[session.clientID] = current
		}
	}
	runtime.mutex.Unlock()
	// Invalidate every local pool before attempting any control-plane delivery.
	for _, session := range sessions {
		if vnetAssignmentChanged(previous, configuration, session.clientID) {
			runtime.broker.Remove(session.clientID, session.sessionID)
		}
	}
	if previous.Enabled && !configuration.Enabled {
		runtime.stopPeerCoordinator()
	}
	if !previous.Enabled && configuration.Enabled {
		if err := runtime.startPeerCoordinator(runtime.peerListenAddress); err != nil {
			runtime.logger.Warn("VNet P2P UDP port is unavailable; relay remains active", err)
		}
	}
	runtime.revokeAllPeers("configuration_changed")
	if device != nil && (!configuration.Enabled || networkChanged) && !canMigrateDevice {
		_ = device.Close()
	}
	if userspaceTCP != nil && (!configuration.Enabled || networkChanged) {
		_ = userspaceTCP.Close()
	}
	var notifications sync.WaitGroup
	for _, session := range sessions {
		notifications.Go(func() {
			runtime.updateSessionConfiguration(session, previous, configuration, generation, networkChanged)
		})
	}
	notifications.Wait()
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

func vnetAssignmentChanged(previous, configuration config.VirtualNetworkConfig, clientID string) bool {
	oldNode, oldExists := config.VNetNode(previous, clientID)
	newNode, newExists := config.VNetNode(configuration, clientID)
	return previous.Enabled != configuration.Enabled || previous.PacketChannels != configuration.PacketChannels ||
		previous.CIDR != configuration.CIDR || previous.ServerIP != configuration.ServerIP ||
		oldExists != newExists || oldNode.IP != newNode.IP
}

func (runtime *serverVNetRuntime) updateSessionConfiguration(
	session serverVNetSessionSnapshot,
	previous, configuration config.VirtualNetworkConfig,
	generation uint64,
	networkChanged bool,
) {
	clientID := session.clientID
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
		if err := session.writer.Write(protocol.MessageVNetDeactivate, protocol.VNetDeactivate{
			ConfigGeneration: generation, Reason: reason,
		}); err != nil {
			_ = session.writer.Close()
			return
		}
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
		if err := runtime.assignLocked(clientID, session.sessionID); err != nil {
			_ = session.writer.Close()
		}
	}
}
