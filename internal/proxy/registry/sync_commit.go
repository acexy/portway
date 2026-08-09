package registry

import (
	"crypto/sha256"
	"net"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
)

type syncCommitPreparation struct {
	clientID              string
	sessionID             string
	requestID             string
	request               protocol.SyncProxies
	fingerprint           [sha256.Size]byte
	baseRevision          uint64
	authenticationMode    authentication.Mode
	results               []protocol.ProxyResult
	existingProxies       map[string]*tcpProxyBinding
	existingUDPProxies    map[string]*udpProxyBinding
	existingHTTPProxies   map[string]*httpProxyBinding
	reusableEndpoints     map[uint16]*proxytcp.Endpoint
	reusableUDPEndpoints  map[uint16]*proxyudp.Endpoint
	newEndpoints          map[uint16]*proxytcp.Endpoint
	newUDPEndpoints       map[uint16]*proxyudp.Endpoint
	nextProxies           map[string]*tcpProxyBinding
	nextUDPProxies        map[string]*udpProxyBinding
	nextHTTPProxies       map[string]*httpProxyBinding
	declarationsByPort    map[uint16]protocol.ProxyDeclaration
	declarationsByUDPPort map[uint16]protocol.ProxyDeclaration
}

func (manager *Registry) commitSync(preparation syncCommitPreparation) protocol.SyncResult {
	clientID := preparation.clientID
	sessionID := preparation.sessionID
	requestID := preparation.requestID
	request := preparation.request
	fingerprint := preparation.fingerprint
	baseRevision := preparation.baseRevision
	authenticationMode := preparation.authenticationMode
	results := preparation.results
	existingProxies := preparation.existingProxies
	existingUDPProxies := preparation.existingUDPProxies
	existingHTTPProxies := preparation.existingHTTPProxies
	reusableEndpoints := preparation.reusableEndpoints
	reusableUDPEndpoints := preparation.reusableUDPEndpoints
	newEndpoints := preparation.newEndpoints
	newUDPEndpoints := preparation.newUDPEndpoints
	nextProxies := preparation.nextProxies
	nextUDPProxies := preparation.nextUDPProxies
	nextHTTPProxies := preparation.nextHTTPProxies
	declarationsByPort := preparation.declarationsByPort
	declarationsByUDPPort := preparation.declarationsByUDPPort

	manager.registrationMutex.Lock()
	defer manager.registrationMutex.Unlock()
	result := protocol.SyncResult{
		Revision: request.Revision,
		Status:   protocol.ProxySyncStatusApplied,
		Proxies:  results,
	}
	manager.mutex.Lock()
	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID || state.revision != baseRevision {
		manager.mutex.Unlock()
		rollbackSyncPreparation(
			newEndpoints,
			newUDPEndpoints,
			nextUDPProxies,
			existingUDPProxies,
			nextHTTPProxies,
			existingHTTPProxies,
		)
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorSessionInactive,
			"",
			"client session changed during registration",
		)
	}
	if reservationRejection := manager.managedReservationRejectionLocked(
		clientID,
		authenticationMode,
		request,
	); reservationRejection != nil {
		manager.mutex.Unlock()
		rollbackSyncPreparation(
			newEndpoints,
			newUDPEndpoints,
			nextUDPProxies,
			existingUDPProxies,
			nextHTTPProxies,
			existingHTTPProxies,
		)
		return *reservationRejection
	}
	for port, endpoint := range reusableEndpoints {
		if manager.endpoints[port] != endpoint ||
			manager.endpointBindings[port] == nil ||
			manager.endpointBindings[port].clientID != clientID ||
			existingProxies[manager.endpointBindings[port].declaration.Name] != manager.endpointBindings[port] {
			manager.mutex.Unlock()
			closeTCPEndpoints(newEndpoints)
			closeUDPEndpoints(newUDPEndpoints)
			closeUDPBindings(nextUDPProxies, existingUDPProxies)
			return rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorPortConflict,
				declarationsByPort[port].Name,
				"remote port ownership changed during registration",
			)
		}
	}
	for port, endpoint := range reusableUDPEndpoints {
		currentBinding := manager.udpEndpointBindings[port]
		if manager.udpEndpoints[port] != endpoint ||
			currentBinding == nil ||
			currentBinding.clientID != clientID ||
			existingUDPProxies[currentBinding.declaration.Name] != currentBinding {
			manager.mutex.Unlock()
			closeTCPEndpoints(newEndpoints)
			closeUDPEndpoints(newUDPEndpoints)
			closeUDPBindings(nextUDPProxies, existingUDPProxies)
			return rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorPortConflict,
				declarationsByUDPPort[port].Name,
				"UDP remote port ownership changed during registration",
			)
		}
	}
	for _, binding := range nextHTTPProxies {
		owner := manager.httpDomains[binding.declaration.Domain]
		if owner != nil && existingHTTPProxies[owner.declaration.Name] != owner {
			manager.mutex.Unlock()
			closeTCPEndpoints(newEndpoints)
			closeUDPEndpoints(newUDPEndpoints)
			closeUDPBindings(nextUDPProxies, existingUDPProxies)
			closeHTTPBindings(nextHTTPProxies, existingHTTPProxies)
			return rejectedSyncResult(request.Revision, protocol.ProxyErrorDomainConflict, binding.declaration.Name, "HTTP domain ownership changed during registration")
		}
	}

	removedProxyNames := make([]string, 0)
	for name, existing := range existingProxies {
		if nextProxies[name] != existing {
			removedProxyNames = append(removedProxyNames, name)
		}
	}
	removedUDPBindings := make([]*udpProxyBinding, 0)
	for name, existing := range existingUDPProxies {
		if nextUDPProxies[name] != existing {
			removedUDPBindings = append(removedUDPBindings, existing)
		}
	}
	removedHTTPBindings := make([]*httpProxyBinding, 0)
	for name, existing := range existingHTTPProxies {
		if nextHTTPProxies[name] != existing {
			removedHTTPBindings = append(removedHTTPBindings, existing)
			if manager.httpDomains[existing.declaration.Domain] == existing {
				delete(manager.httpDomains, existing.declaration.Domain)
			}
		}
	}
	nextEndpoints := make(map[uint16]*proxytcp.Endpoint, len(request.Proxies))
	for _, binding := range nextProxies {
		binding.sessionID = sessionID
		binding.endpoint.SetHandler(func(visitor net.Conn) {
			manager.openVisitor(binding.endpoint, binding, visitor)
		})
		nextEndpoints[binding.declaration.RemotePort] = binding.endpoint
		manager.endpoints[binding.declaration.RemotePort] = binding.endpoint
		manager.endpointBindings[binding.declaration.RemotePort] = binding
	}
	removedEndpoints := make(map[uint16]*proxytcp.Endpoint)
	for _, existing := range existingProxies {
		endpoint := existing.endpoint
		remotePort := existing.declaration.RemotePort
		if nextEndpoints[remotePort] != endpoint {
			if manager.endpoints[remotePort] == endpoint {
				delete(manager.endpoints, existing.declaration.RemotePort)
				delete(manager.endpointBindings, existing.declaration.RemotePort)
			}
			removedEndpoints[existing.declaration.RemotePort] = endpoint
		}
	}
	nextUDPEndpoints := make(map[uint16]*proxyudp.Endpoint, len(nextUDPProxies))
	for _, binding := range nextUDPProxies {
		binding.sessionID = sessionID
		binding.endpoint.SetHandler(binding.runtime.HandleDatagram)
		nextUDPEndpoints[binding.declaration.RemotePort] = binding.endpoint
		manager.udpEndpoints[binding.declaration.RemotePort] = binding.endpoint
		manager.udpEndpointBindings[binding.declaration.RemotePort] = binding
	}
	removedUDPEndpoints := make(map[uint16]*proxyudp.Endpoint)
	for _, existing := range existingUDPProxies {
		endpoint := existing.endpoint
		remotePort := existing.declaration.RemotePort
		if nextUDPEndpoints[remotePort] != endpoint {
			if manager.udpEndpoints[remotePort] == endpoint {
				delete(manager.udpEndpoints, remotePort)
				delete(manager.udpEndpointBindings, remotePort)
			}
			removedUDPEndpoints[remotePort] = endpoint
		}
	}
	state.tcpProxies = nextProxies
	state.udpProxies = nextUDPProxies
	state.httpProxies = nextHTTPProxies
	for _, binding := range nextHTTPProxies {
		manager.httpDomains[binding.declaration.Domain] = binding
	}
	state.revision = request.Revision
	state.fingerprint = fingerprint
	state.lastRequestID = requestID
	state.lastResult = result
	state.cacheSyncRequest(requestID, request.Revision, fingerprint, result)
	manager.mutex.Unlock()

	for _, endpoint := range newEndpoints {
		endpoint.Start()
	}
	for _, endpoint := range newUDPEndpoints {
		endpoint.Start()
	}
	closeTCPEndpoints(removedEndpoints)
	closeUDPEndpoints(removedUDPEndpoints)
	for _, name := range removedProxyNames {
		manager.linkBroker.CancelBinding(existingProxies[name].bindingID)
	}
	for _, binding := range removedHTTPBindings {
		binding.close()
	}
	for _, binding := range removedUDPBindings {
		manager.linkBroker.CancelBinding(binding.bindingID)
		binding.close()
	}
	return result
}
