package registry

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/proxy/mirror"
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
			for _, port := range groupConfiguration.Public.Ports() {
				group := &mirrorGroup{
					configuration: groupConfiguration,
					port:          port,
					mode:          mode,
					tcpMembers:    make(map[string]*tcpProxyBinding),
					udpMembers:    make(map[string]*udpProxyBinding),
					tcpSessions:   make(map[*mirror.TCPSession]struct{}),
				}
				if groupConfiguration.Type == protocol.ProxyTypeTCP {
					candidatesTCP[port] = group
				} else {
					candidatesUDP[port] = group
				}
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

	manager.mutex.Lock()
	removedTCP := make(map[uint16]*proxytcp.Endpoint)
	removedUDP := make(map[uint16]*proxyudp.Endpoint)
	removedBindings := make([]string, 0)
	removedUDPBindings := make([]*udpProxyBinding, 0)
	for port, old := range manager.tcpMirrorGroups {
		candidate := candidatesTCP[port]
		if candidate == nil || candidate.mode != old.mode {
			for session := range old.tcpSessions {
				session.Cancel()
			}
		}
		if candidate == nil {
			if old.tcpEndpoint != nil {
				removedTCP[port] = old.tcpEndpoint
			}
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
			if old.udpEndpoint != nil {
				removedUDP[port] = old.udpEndpoint
			}
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
	// Keep the live-session owner stable when an endpoint remains authorized.
	for port, candidate := range candidatesTCP {
		if old := manager.tcpMirrorGroups[port]; old != nil && old.mode == candidate.mode {
			old.configuration = candidate.configuration
			old.tcpMembers = candidate.tcpMembers
			candidatesTCP[port] = old
		}
	}
	for port, candidate := range candidatesTCP {
		if len(candidate.tcpMembers) == 0 && candidate.tcpEndpoint != nil {
			for session := range candidate.tcpSessions {
				session.Cancel()
			}
			removedTCP[port] = candidate.tcpEndpoint
			candidate.tcpEndpoint = nil
		}
	}
	for port, candidate := range candidatesUDP {
		if len(candidate.udpMembers) == 0 && candidate.udpEndpoint != nil {
			removedUDP[port] = candidate.udpEndpoint
			candidate.udpEndpoint = nil
		}
	}
	manager.tcpMirrorGroups = candidatesTCP
	manager.udpMirrorGroups = candidatesUDP
	for port, group := range candidatesTCP {
		if group.tcpEndpoint == nil {
			continue
		}
		manager.endpoints[port] = group.tcpEndpoint
		delete(manager.endpointBindings, port)
		groupSnapshot := group
		group.tcpEndpoint.SetHandler(func(visitor net.Conn) {
			go manager.openMirrorVisitor(groupSnapshot, visitor)
		})
	}
	for port, group := range candidatesUDP {
		if group.udpEndpoint == nil {
			continue
		}
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
	responseUpdates := make(map[*mirror.TCPSession]string)
	var joins []mirrorTCPJoin
	for _, group := range candidatesTCP {
		for session := range group.tcpSessions {
			responseUpdates[session] = group.configuration.PrimaryClientID
		}
	}
	for clientID, state := range manager.clients {
		if state.active {
			joins = append(joins, manager.mirrorTCPJoinsLocked(clientID, state)...)
		}
	}
	manager.mutex.Unlock()

	// Publish response eligibility without waiting for an in-flight bounded write.
	for session, primary := range responseUpdates {
		session.SetPrimary(primary)
	}
	for _, join := range joins {
		join.session.AddTarget(join.target)
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
	if manager.udpMirrorGroups[group.port] != group {
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
