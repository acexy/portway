package registry

import (
	"sync"

	"github.com/acexy/golang-toolkit/util/coll"

	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
)

// Activate makes a fully registered client available to public traffic.
func (manager *Registry) Activate(clientID string, sessionID string) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		return
	}
	state.active = true
}

// Active reports whether the specified Session currently accepts public traffic.
func (manager *Registry) Active(clientID string, sessionID string) bool {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	state, exists := manager.clients[clientID]
	return exists && state.sessionID == sessionID && state.active
}

// Deactivate rejects new traffic without releasing the current proxy generation.
func (manager *Registry) Deactivate(clientID string, sessionID string) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		return
	}
	state.active = false
}

// Suspend rejects new traffic and closes links for a disconnected session.
func (manager *Registry) Suspend(clientID string, sessionID string) {
	manager.mutex.Lock()
	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		manager.mutex.Unlock()
		return
	}
	state.active = false
	httpBindings := coll.MapValues(state.httpProxies)
	udpBindings := coll.MapValues(state.udpProxies)
	manager.mutex.Unlock()

	manager.linkBroker.CancelSession(clientID, sessionID)
	for _, binding := range httpBindings {
		binding.runtime.CloseIdleConnections()
	}
	for _, binding := range udpBindings {
		binding.runtime.Suspend()
	}
}

// Remove permanently releases every proxy owned by one session.
func (manager *Registry) Remove(clientID string, sessionID string) {
	manager.Detach(clientID, sessionID)()
}

// Detach atomically removes a Session's routes and returns an idempotent
// cleanup callback for potentially blocking resource closure outside locks.
func (manager *Registry) Detach(clientID string, sessionID string) func() {
	manager.registrationMutex.Lock()
	defer manager.registrationMutex.Unlock()

	manager.mutex.Lock()
	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		manager.mutex.Unlock()
		return func() {}
	}
	delete(manager.clients, clientID)
	endpoints := make(map[uint16]*proxytcp.Endpoint, len(state.tcpProxies))
	for _, binding := range state.tcpProxies {
		endpoint := binding.endpoint
		if group := manager.tcpMirrorGroups[binding.declaration.RemotePort]; group != nil &&
			group.tcpMembers[clientID] == binding {
			delete(group.tcpMembers, clientID)
		} else if manager.endpoints[binding.declaration.RemotePort] == endpoint {
			delete(manager.endpoints, binding.declaration.RemotePort)
			delete(manager.endpointBindings, binding.declaration.RemotePort)
			endpoints[binding.declaration.RemotePort] = endpoint
		}
	}
	udpEndpoints := make(map[uint16]*proxyudp.Endpoint, len(state.udpProxies))
	udpBindings := make([]*udpProxyBinding, 0, len(state.udpProxies))
	for _, binding := range state.udpProxies {
		endpoint := binding.endpoint
		if group := manager.udpMirrorGroups[binding.declaration.RemotePort]; group != nil &&
			group.udpMembers[clientID] == binding {
			delete(group.udpMembers, clientID)
		} else if manager.udpEndpoints[binding.declaration.RemotePort] == endpoint {
			delete(manager.udpEndpoints, binding.declaration.RemotePort)
			delete(manager.udpEndpointBindings, binding.declaration.RemotePort)
			udpEndpoints[binding.declaration.RemotePort] = endpoint
		}
		udpBindings = append(udpBindings, binding)
	}
	httpBindings := make([]*httpProxyBinding, 0, len(state.httpProxies))
	for _, binding := range state.httpProxies {
		if manager.httpDomains[binding.declaration.Domain] == binding {
			delete(manager.httpDomains, binding.declaration.Domain)
		}
		httpBindings = append(httpBindings, binding)
	}
	manager.mutex.Unlock()

	var closeOnce sync.Once
	return func() {
		closeOnce.Do(func() {
			closeTCPEndpoints(endpoints)
			closeUDPEndpoints(udpEndpoints)
			manager.linkBroker.CancelSession(clientID, sessionID)
			for _, binding := range httpBindings {
				binding.close()
			}
			for _, binding := range udpBindings {
				binding.close()
			}
		})
	}
}

// Close releases all registry-owned resources.
func (manager *Registry) Close() {
	manager.registrationMutex.Lock()
	defer manager.registrationMutex.Unlock()

	manager.mutex.Lock()
	manager.closed = true
	endpoints := make(map[uint16]*proxytcp.Endpoint, len(manager.endpoints))
	udpEndpoints := make(map[uint16]*proxyudp.Endpoint, len(manager.udpEndpoints))
	udpBindings := make([]*udpProxyBinding, 0)
	httpBindings := coll.MapValues(manager.httpDomains)
	for port, endpoint := range manager.endpoints {
		endpoints[port] = endpoint
	}
	for port, endpoint := range manager.udpEndpoints {
		udpEndpoints[port] = endpoint
	}
	for _, state := range manager.clients {
		for _, binding := range state.udpProxies {
			udpBindings = append(udpBindings, binding)
		}
	}
	manager.clients = make(map[string]*clientState)
	manager.endpoints = make(map[uint16]*proxytcp.Endpoint)
	manager.endpointBindings = make(map[uint16]*tcpProxyBinding)
	manager.udpEndpoints = make(map[uint16]*proxyudp.Endpoint)
	manager.udpEndpointBindings = make(map[uint16]*udpProxyBinding)
	manager.tcpMirrorGroups = make(map[uint16]*mirrorGroup)
	manager.udpMirrorGroups = make(map[uint16]*mirrorGroup)
	manager.httpDomains = make(map[string]*httpProxyBinding)
	manager.mutex.Unlock()

	closeTCPEndpoints(endpoints)
	closeUDPEndpoints(udpEndpoints)
	for _, binding := range udpBindings {
		binding.close()
	}
	for _, binding := range httpBindings {
		binding.close()
	}
}

func closeTCPEndpoints(endpoints map[uint16]*proxytcp.Endpoint) {
	for _, endpoint := range endpoints {
		endpoint.Close()
	}
}
