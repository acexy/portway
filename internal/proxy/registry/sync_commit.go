package registry

import (
	"crypto/sha256"
	"net"
	"net/netip"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
)

type syncCommitPreparation struct {
	clientID              string
	sessionID             string
	requestID             string
	request               SyncRequest
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

func (manager *Registry) commitSync(preparation syncCommitPreparation) SyncResult {
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
	result := SyncResult{
		Revision: request.Revision,
		Status:   SyncStatusApplied,
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
			ErrorSessionInactive,
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
		group := manager.tcpMirrorGroups[port]
		mirrorOwned := group != nil && group.tcpEndpoint == endpoint &&
			group.allows(clientID, manager.clients[clientID])
		ordinaryOwned := manager.endpointBindings[port] != nil &&
			manager.endpointBindings[port].clientID == clientID &&
			existingProxies[manager.endpointBindings[port].declaration.Name] == manager.endpointBindings[port]
		if manager.endpoints[port] != endpoint || !mirrorOwned && !ordinaryOwned {
			manager.mutex.Unlock()
			closeTCPEndpoints(newEndpoints)
			closeUDPEndpoints(newUDPEndpoints)
			closeUDPBindings(nextUDPProxies, existingUDPProxies)
			return rejectedSyncResult(
				request.Revision,
				ErrorPortConflict,
				declarationsByPort[port].Name,
				"remote port ownership changed during registration",
			)
		}
	}
	for port, endpoint := range reusableUDPEndpoints {
		currentBinding := manager.udpEndpointBindings[port]
		group := manager.udpMirrorGroups[port]
		mirrorOwned := group != nil && group.udpEndpoint == endpoint &&
			group.allows(clientID, manager.clients[clientID])
		ordinaryOwned := currentBinding != nil && currentBinding.clientID == clientID &&
			existingUDPProxies[currentBinding.declaration.Name] == currentBinding
		if manager.udpEndpoints[port] != endpoint || !mirrorOwned && !ordinaryOwned {
			manager.mutex.Unlock()
			closeTCPEndpoints(newEndpoints)
			closeUDPEndpoints(newUDPEndpoints)
			closeUDPBindings(nextUDPProxies, existingUDPProxies)
			return rejectedSyncResult(
				request.Revision,
				ErrorPortConflict,
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
			return rejectedSyncResult(request.Revision, ErrorDomainConflict, binding.declaration.Name, "HTTP domain ownership changed during registration")
		}
	}

	removedProxyNames := coll.MapFilterToSlice(existingProxies, func(name string, existing *tcpProxyBinding) (string, bool) {
		return name, nextProxies[name] != existing
	})
	removedUDPBindings := coll.MapFilterToSlice(existingUDPProxies, func(name string, existing *udpProxyBinding) (*udpProxyBinding, bool) {
		return existing, nextUDPProxies[name] != existing
	})
	removedHTTPBindings := coll.MapFilterToSlice(existingHTTPProxies, func(name string, existing *httpProxyBinding) (*httpProxyBinding, bool) {
		removed := nextHTTPProxies[name] != existing
		if removed && manager.httpDomains[existing.declaration.Domain] == existing {
			delete(manager.httpDomains, existing.declaration.Domain)
		}
		return existing, removed
	})
	nextEndpoints := make(map[uint16]*proxytcp.Endpoint, len(request.Proxies))
	for _, binding := range nextProxies {
		binding.sessionID = sessionID
		if group := manager.tcpMirrorGroups[binding.declaration.RemotePort]; group != nil &&
			group.allows(clientID, state) {
			if group.tcpEndpoint == nil {
				group.tcpEndpoint = binding.endpoint
				groupSnapshot := group
				group.tcpEndpoint.SetHandler(func(visitor net.Conn) {
					go manager.openMirrorVisitor(groupSnapshot, visitor)
				})
			}
			group.tcpMembers[clientID] = binding
			delete(manager.endpointBindings, binding.declaration.RemotePort)
		} else {
			binding.endpoint.SetHandler(func(visitor net.Conn) {
				manager.openVisitor(binding.endpoint, binding, visitor)
			})
			manager.endpointBindings[binding.declaration.RemotePort] = binding
		}
		nextEndpoints[binding.declaration.RemotePort] = binding.endpoint
		manager.endpoints[binding.declaration.RemotePort] = binding.endpoint
	}
	removedEndpoints := make(map[uint16]*proxytcp.Endpoint)
	for _, existing := range existingProxies {
		endpoint := existing.endpoint
		remotePort := existing.declaration.RemotePort
		if group := manager.tcpMirrorGroups[remotePort]; group != nil &&
			group.tcpMembers[clientID] == existing && nextProxies[existing.declaration.Name] != existing {
			delete(group.tcpMembers, clientID)
		}
		if nextEndpoints[remotePort] != endpoint && manager.tcpMirrorGroups[remotePort] == nil {
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
		if group := manager.udpMirrorGroups[binding.declaration.RemotePort]; group != nil &&
			group.allows(clientID, state) {
			if group.udpEndpoint == nil {
				group.udpEndpoint = binding.endpoint
				groupSnapshot := group
				group.udpEndpoint.SetHandler(func(source netip.AddrPort, payload []byte) {
					manager.handleMirrorDatagram(groupSnapshot, source, payload)
				})
			}
			binding.runtime.SetResponseEnabled(clientID == group.configuration.PrimaryClientID)
			group.udpMembers[clientID] = binding
			delete(manager.udpEndpointBindings, binding.declaration.RemotePort)
		} else {
			binding.endpoint.SetHandler(binding.runtime.HandleDatagram)
			manager.udpEndpointBindings[binding.declaration.RemotePort] = binding
		}
		nextUDPEndpoints[binding.declaration.RemotePort] = binding.endpoint
		manager.udpEndpoints[binding.declaration.RemotePort] = binding.endpoint
	}
	removedUDPEndpoints := make(map[uint16]*proxyudp.Endpoint)
	for _, existing := range existingUDPProxies {
		endpoint := existing.endpoint
		remotePort := existing.declaration.RemotePort
		if group := manager.udpMirrorGroups[remotePort]; group != nil &&
			group.udpMembers[clientID] == existing && nextUDPProxies[existing.declaration.Name] != existing {
			delete(group.udpMembers, clientID)
		}
		if nextUDPEndpoints[remotePort] != endpoint && manager.udpMirrorGroups[remotePort] == nil {
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
