package registry

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
)

// ConfigureMirrorGroups atomically replaces the server-owned mirror group set.
func (manager *Registry) ConfigureMirrorGroups(configuration config.ProxyMirrorConfig) error {
	manager.registrationMutex.Lock()
	defer manager.registrationMutex.Unlock()
	return manager.configureMirrorGroupsLocked(configuration)
}

func (manager *Registry) configureMirrorGroupsLocked(configuration config.ProxyMirrorConfig) error {
	candidatesTCP := make(map[uint16]*mirrorGroup)
	candidatesUDP := make(map[uint16]*mirrorGroup)
	appendGroups := func(mode authentication.Mode, groups []config.ProxyMirrorGroupConfig) {
		for _, groupConfiguration := range groups {
			group := &mirrorGroup{
				configuration: groupConfiguration,
				mode:          mode,
				tcpMembers:    make(map[string]*tcpProxyBinding),
				udpMembers:    make(map[string]*udpProxyBinding),
			}
			if groupConfiguration.Type == protocol.ProxyTypeTCP {
				candidatesTCP[groupConfiguration.Public.Port] = group
			} else {
				candidatesUDP[groupConfiguration.Public.Port] = group
			}
		}
	}
	appendGroups(authentication.ModeGoverned, configuration.Governed)
	appendGroups(authentication.ModeManaged, configuration.Managed)

	manager.mutex.Lock()
	if manager.closed {
		manager.mutex.Unlock()
		return fmt.Errorf("proxy registry is closed")
	}
	for port, candidate := range candidatesTCP {
		if existing := manager.tcpMirrorGroups[port]; existing != nil {
			candidate.tcpEndpoint = existing.tcpEndpoint
			for clientID, binding := range existing.tcpMembers {
				if candidate.allows(clientID, manager.clients[clientID]) {
					candidate.tcpMembers[clientID] = binding
				}
			}
			continue
		}
		if endpoint := manager.endpoints[port]; endpoint != nil {
			binding := manager.endpointBindings[port]
			state := (*clientState)(nil)
			if binding != nil {
				state = manager.clients[binding.clientID]
			}
			if binding == nil || !candidate.allows(binding.clientID, state) {
				manager.mutex.Unlock()
				return fmt.Errorf("mirror TCP port %d is already in use", port)
			}
			candidate.tcpEndpoint = endpoint
			candidate.tcpMembers[binding.clientID] = binding
		}
	}
	for port, candidate := range candidatesUDP {
		if existing := manager.udpMirrorGroups[port]; existing != nil {
			candidate.udpEndpoint = existing.udpEndpoint
			for clientID, binding := range existing.udpMembers {
				if candidate.allows(clientID, manager.clients[clientID]) {
					candidate.udpMembers[clientID] = binding
				}
			}
			continue
		}
		if endpoint := manager.udpEndpoints[port]; endpoint != nil {
			binding := manager.udpEndpointBindings[port]
			state := (*clientState)(nil)
			if binding != nil {
				state = manager.clients[binding.clientID]
			}
			if binding == nil || !candidate.allows(binding.clientID, state) {
				manager.mutex.Unlock()
				return fmt.Errorf("mirror UDP port %d is already in use", port)
			}
			candidate.udpEndpoint = endpoint
			candidate.udpMembers[binding.clientID] = binding
		}
	}
	manager.mutex.Unlock()

	newTCPEndpoints := make(map[uint16]*proxytcp.Endpoint)
	newUDPEndpoints := make(map[uint16]*proxyudp.Endpoint)
	rollback := func() {
		closeTCPEndpoints(newTCPEndpoints)
		closeUDPEndpoints(newUDPEndpoints)
	}
	for port, candidate := range candidatesTCP {
		if candidate.tcpEndpoint != nil {
			continue
		}
		endpoint, err := proxytcp.Listen(
			manager.context,
			manager.logger.WithComponent("proxy_mirror_tcp"),
			net.JoinHostPort(manager.proxyBindIP, strconv.Itoa(int(port))),
			manager.sourceFilter,
		)
		if err != nil {
			rollback()
			return fmt.Errorf("listen on mirror TCP port %d: %w", port, err)
		}
		candidate.tcpEndpoint = endpoint
		newTCPEndpoints[port] = endpoint
	}
	for port, candidate := range candidatesUDP {
		if candidate.udpEndpoint != nil {
			continue
		}
		endpoint, err := proxyudp.Listen(
			manager.context,
			manager.logger.WithComponent("proxy_mirror_udp"),
			net.JoinHostPort(manager.proxyBindIP, strconv.Itoa(int(port))),
			manager.sourceFilter,
			manager.udpConfiguration.MaxDatagramSize,
		)
		if err != nil {
			rollback()
			return fmt.Errorf("listen on mirror UDP port %d: %w", port, err)
		}
		candidate.udpEndpoint = endpoint
		newUDPEndpoints[port] = endpoint
	}

	manager.mutex.Lock()
	removedTCP := make(map[uint16]*proxytcp.Endpoint)
	removedUDP := make(map[uint16]*proxyudp.Endpoint)
	removedBindings := make([]string, 0)
	removedUDPBindings := make([]*udpProxyBinding, 0)
	for port, old := range manager.tcpMirrorGroups {
		candidate := candidatesTCP[port]
		if candidate == nil {
			removedTCP[port] = old.tcpEndpoint
			for _, binding := range old.tcpMembers {
				removedBindings = append(removedBindings, binding.bindingID)
				if state := manager.clients[binding.clientID]; state != nil &&
					state.tcpProxies[binding.declaration.Name] == binding {
					delete(state.tcpProxies, binding.declaration.Name)
				}
			}
			continue
		}
		for clientID, binding := range old.tcpMembers {
			if candidate.tcpMembers[clientID] != binding {
				removedBindings = append(removedBindings, binding.bindingID)
				if state := manager.clients[binding.clientID]; state != nil &&
					state.tcpProxies[binding.declaration.Name] == binding {
					delete(state.tcpProxies, binding.declaration.Name)
				}
			}
		}
	}
	for port, old := range manager.udpMirrorGroups {
		candidate := candidatesUDP[port]
		if candidate == nil {
			removedUDP[port] = old.udpEndpoint
			for _, binding := range old.udpMembers {
				removedUDPBindings = append(removedUDPBindings, binding)
				if state := manager.clients[binding.clientID]; state != nil &&
					state.udpProxies[binding.declaration.Name] == binding {
					delete(state.udpProxies, binding.declaration.Name)
				}
			}
			continue
		}
		for clientID, binding := range old.udpMembers {
			if candidate.udpMembers[clientID] != binding {
				removedUDPBindings = append(removedUDPBindings, binding)
				if state := manager.clients[binding.clientID]; state != nil &&
					state.udpProxies[binding.declaration.Name] == binding {
					delete(state.udpProxies, binding.declaration.Name)
				}
			}
		}
	}
	manager.tcpMirrorGroups = candidatesTCP
	manager.udpMirrorGroups = candidatesUDP
	for port, group := range candidatesTCP {
		manager.endpoints[port] = group.tcpEndpoint
		delete(manager.endpointBindings, port)
		groupSnapshot := group
		group.tcpEndpoint.SetHandler(func(visitor net.Conn) {
			go manager.openMirrorVisitor(groupSnapshot, visitor)
		})
	}
	for port, group := range candidatesUDP {
		manager.udpEndpoints[port] = group.udpEndpoint
		delete(manager.udpEndpointBindings, port)
		groupSnapshot := group
		group.udpEndpoint.SetHandler(func(source netip.AddrPort, payload []byte) {
			manager.handleMirrorDatagram(groupSnapshot, source, payload)
		})
		for clientID, binding := range group.udpMembers {
			binding.runtime.SetResponseEnabled(clientID == group.configuration.PrimaryClientID)
		}
	}
	for port := range removedTCP {
		delete(manager.endpoints, port)
	}
	for port := range removedUDP {
		delete(manager.udpEndpoints, port)
	}
	manager.mutex.Unlock()

	for _, endpoint := range newTCPEndpoints {
		endpoint.Start()
	}
	for _, endpoint := range newUDPEndpoints {
		endpoint.Start()
	}
	closeTCPEndpoints(removedTCP)
	closeUDPEndpoints(removedUDP)
	for _, bindingID := range removedBindings {
		manager.linkBroker.CancelBinding(bindingID)
	}
	for _, binding := range removedUDPBindings {
		binding.close()
	}
	return nil
}

func (group *mirrorGroup) allows(clientID string, state *clientState) bool {
	if state == nil || state.authentication.Mode != group.mode {
		return false
	}
	return group.allowsMode(clientID, state.authentication.Mode)
}

func (group *mirrorGroup) allowsMode(clientID string, mode authentication.Mode) bool {
	if group.mode != mode {
		return false
	}
	for _, allowedClientID := range group.configuration.ClientIDs {
		if allowedClientID == clientID {
			return true
		}
	}
	return false
}

func (manager *Registry) mirrorGroupLocked(
	clientID string,
	state *clientState,
	declaration protocol.ProxyDeclaration,
) *mirrorGroup {
	var group *mirrorGroup
	if declaration.Type == protocol.ProxyTypeTCP {
		group = manager.tcpMirrorGroups[declaration.RemotePort]
	} else if declaration.Type == protocol.ProxyTypeUDP {
		group = manager.udpMirrorGroups[declaration.RemotePort]
	}
	if group == nil || !group.allows(clientID, state) {
		return nil
	}
	return group
}

func (manager *Registry) handleMirrorDatagram(
	group *mirrorGroup,
	source netip.AddrPort,
	payload []byte,
) {
	manager.mutex.Lock()
	if manager.udpMirrorGroups[group.configuration.Public.Port] != group {
		manager.mutex.Unlock()
		return
	}
	bindings := make([]*udpProxyBinding, 0, len(group.udpMembers))
	for _, binding := range group.udpMembers {
		state := manager.clients[binding.clientID]
		if state != nil && state.active && state.sessionID == binding.sessionID &&
			state.udpProxies[binding.declaration.Name] == binding {
			bindings = append(bindings, binding)
		}
	}
	manager.mutex.Unlock()
	for _, binding := range bindings {
		binding.runtime.HandleDatagram(source, payload)
	}
}
