package registry

import proxytcp "github.com/acexy/portway/internal/proxy/tcp"

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

// Suspend rejects new traffic and closes links for a disconnected session.
func (manager *Registry) Suspend(clientID string, sessionID string) {
	manager.mutex.Lock()
	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		manager.mutex.Unlock()
		return
	}
	state.active = false
	state.writer = nil
	httpBindings := make([]*httpProxyBinding, 0, len(state.httpProxies))
	for _, binding := range state.httpProxies {
		httpBindings = append(httpBindings, binding)
	}
	manager.mutex.Unlock()

	manager.linkBroker.CancelSession(clientID, sessionID)
	for _, binding := range httpBindings {
		binding.runtime.CloseIdleConnections()
	}
}

// Remove permanently releases every proxy owned by one session.
func (manager *Registry) Remove(clientID string, sessionID string) {
	manager.registrationMutex.Lock()
	defer manager.registrationMutex.Unlock()

	manager.mutex.Lock()
	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		manager.mutex.Unlock()
		return
	}
	delete(manager.clients, clientID)
	endpoints := make(map[uint16]*proxytcp.Endpoint, len(state.tcpProxies))
	for _, binding := range state.tcpProxies {
		endpoint := binding.endpoint
		if manager.endpoints[binding.declaration.RemotePort] == endpoint {
			delete(manager.endpoints, binding.declaration.RemotePort)
			delete(manager.endpointBindings, binding.declaration.RemotePort)
		}
		endpoints[binding.declaration.RemotePort] = endpoint
	}
	httpBindings := make([]*httpProxyBinding, 0, len(state.httpProxies))
	for _, binding := range state.httpProxies {
		if manager.httpDomains[binding.declaration.Domain] == binding {
			delete(manager.httpDomains, binding.declaration.Domain)
		}
		httpBindings = append(httpBindings, binding)
	}
	manager.mutex.Unlock()

	closeTCPEndpoints(endpoints)
	manager.linkBroker.CancelSession(clientID, sessionID)
	for _, binding := range httpBindings {
		binding.close()
	}
}

// Close releases all registry-owned resources.
func (manager *Registry) Close() {
	manager.registrationMutex.Lock()
	defer manager.registrationMutex.Unlock()

	manager.mutex.Lock()
	manager.closed = true
	endpoints := make(map[uint16]*proxytcp.Endpoint, len(manager.endpoints))
	httpBindings := make([]*httpProxyBinding, 0, len(manager.httpDomains))
	for port, endpoint := range manager.endpoints {
		endpoints[port] = endpoint
	}
	for _, binding := range manager.httpDomains {
		httpBindings = append(httpBindings, binding)
	}
	manager.clients = make(map[string]*clientState)
	manager.endpoints = make(map[uint16]*proxytcp.Endpoint)
	manager.endpointBindings = make(map[uint16]*tcpProxyBinding)
	manager.httpDomains = make(map[string]*httpProxyBinding)
	manager.mutex.Unlock()

	closeTCPEndpoints(endpoints)
	for _, binding := range httpBindings {
		binding.close()
	}
}

func closeTCPEndpoints(endpoints map[uint16]*proxytcp.Endpoint) {
	for _, endpoint := range endpoints {
		endpoint.Close()
	}
}
