package registry

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
)

func (manager *Registry) Sync(
	clientID string,
	sessionID string,
	requestID string,
	request SyncRequest,
) SyncResult {
	return manager.sync(clientID, sessionID, requestID, request, false)
}

// SyncAllowEmpty applies a Proxy set that may be empty when a Forward exists.
func (manager *Registry) SyncAllowEmpty(
	clientID string,
	sessionID string,
	requestID string,
	request SyncRequest,
) SyncResult {
	return manager.sync(clientID, sessionID, requestID, request, true)
}

func (manager *Registry) sync(
	clientID string,
	sessionID string,
	requestID string,
	request SyncRequest,
	allowEmpty bool,
) SyncResult {
	manager.registrationMutex.Lock()
	registrationLocked := true
	defer func() {
		if registrationLocked {
			manager.registrationMutex.Unlock()
		}
	}()

	if err := protocol.ValidateRequestID(requestID); err != nil {
		return rejectedSyncResult(
			request.Revision,
			ErrorInvalidRequest,
			"",
			err.Error(),
		)
	}
	fingerprintBytes, err := json.Marshal(request.Proxies)
	if err != nil {
		return rejectedSyncResult(request.Revision, ErrorInvalidRequest, "", "encode proxy declaration")
	}
	fingerprint := sha256.Sum256(fingerprintBytes)

	manager.mutex.Lock()
	if manager.closed {
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			ErrorSessionInactive,
			"",
			"proxy registry is closed",
		)
	}
	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			ErrorSessionInactive,
			"",
			"client session is not active",
		)
	}
	if cached, ok := state.requestCache[requestID]; ok {
		if request.Revision == cached.revision &&
			subtle.ConstantTimeCompare(fingerprint[:], cached.fingerprint[:]) == 1 {
			manager.mutex.Unlock()
			return cached.result
		}
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			ErrorInvalidRequest,
			"",
			"proxy request ID payload changed",
		)
	}
	if request.Revision == 0 || request.Revision < state.revision {
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			ErrorInvalidRequest,
			"",
			"proxy revision is stale",
		)
	}
	if request.Revision == state.revision {
		if subtle.ConstantTimeCompare(fingerprint[:], state.fingerprint[:]) == 1 {
			result := state.lastResult
			manager.mutex.Unlock()
			return result
		}
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			ErrorInvalidRequest,
			"",
			"proxy revision payload changed",
		)
	}
	if len(request.Proxies) > maxProxiesPerClient {
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			ErrorCapacityExceeded,
			"",
			"proxy limit exceeded",
		)
	}
	existingProxies := make(map[string]*tcpProxyBinding, len(state.tcpProxies))
	for name, binding := range state.tcpProxies {
		existingProxies[name] = binding
	}
	existingUDPProxies := make(map[string]*udpProxyBinding, len(state.udpProxies))
	for name, binding := range state.udpProxies {
		existingUDPProxies[name] = binding
	}
	existingHTTPProxies := make(map[string]*httpProxyBinding, len(state.httpProxies))
	for name, binding := range state.httpProxies {
		existingHTTPProxies[name] = binding
	}
	authenticationMode := state.authentication.Mode
	baseRevision := state.revision
	manager.mutex.Unlock()

	if !allowEmpty && authenticationMode != authentication.ModeManaged && len(request.Proxies) == 0 {
		return rejectedSyncResult(
			request.Revision,
			ErrorInvalidProxy,
			"",
			"at least one proxy declaration is required",
		)
	}
	if rejection := validateProxyDeclarations(
		request.Revision,
		request.Proxies,
		manager.httpEnabled,
		manager.httpsEnabled,
	); rejection != nil {
		return *rejection
	}
	manager.mutex.Lock()
	reservationRejection := manager.managedReservationRejectionLocked(
		clientID,
		authenticationMode,
		request,
	)
	manager.mutex.Unlock()
	if reservationRejection != nil {
		return *reservationRejection
	}
	declarationsByPort := make(map[uint16]protocol.ProxyDeclaration)
	declarationsByUDPPort := make(map[uint16]protocol.ProxyDeclaration)
	for _, declaration := range request.Proxies {
		switch declaration.Type {
		case protocol.ProxyTypeTCP:
			declarationsByPort[declaration.RemotePort] = declaration
		case protocol.ProxyTypeUDP:
			declarationsByUDPPort[declaration.RemotePort] = declaration
		}
	}

	manager.mutex.Lock()
	reusableEndpoints := make(map[uint16]*proxytcp.Endpoint, len(request.Proxies))
	for _, declaration := range request.Proxies {
		if declaration.Type != protocol.ProxyTypeTCP {
			continue
		}
		endpoint := manager.endpoints[declaration.RemotePort]
		state := manager.clients[clientID]
		if group := manager.mirrorGroupLocked(clientID, state, declaration); group != nil {
			if endpoint != nil && group.tcpEndpoint == endpoint {
				reusableEndpoints[declaration.RemotePort] = endpoint
			}
			continue
		}
		if manager.tcpMirrorGroups[declaration.RemotePort] != nil {
			manager.mutex.Unlock()
			return rejectedSyncResult(
				request.Revision,
				ErrorMirrorMemberNotAllowed,
				declaration.Name,
				"mirror group membership is not allowed",
			)
		}
		if endpoint == nil {
			continue
		}
		currentBinding := manager.endpointBindings[declaration.RemotePort]
		if currentBinding == nil || currentBinding.clientID != clientID {
			manager.mutex.Unlock()
			return rejectedSyncResult(
				request.Revision,
				ErrorPortConflict,
				declaration.Name,
				"remote port is unavailable",
			)
		}
		if existingProxies[currentBinding.declaration.Name] != currentBinding {
			manager.mutex.Unlock()
			return rejectedSyncResult(
				request.Revision,
				ErrorPortConflict,
				declaration.Name,
				"remote port is unavailable",
			)
		}
		reusableEndpoints[declaration.RemotePort] = endpoint
	}
	manager.mutex.Unlock()

	manager.mutex.Lock()
	reusableUDPEndpoints := make(map[uint16]*proxyudp.Endpoint, len(request.Proxies))
	for _, declaration := range request.Proxies {
		if declaration.Type != protocol.ProxyTypeUDP {
			continue
		}
		endpoint := manager.udpEndpoints[declaration.RemotePort]
		state := manager.clients[clientID]
		if group := manager.mirrorGroupLocked(clientID, state, declaration); group != nil {
			if endpoint != nil && group.udpEndpoint == endpoint {
				reusableUDPEndpoints[declaration.RemotePort] = endpoint
			}
			continue
		}
		if manager.udpMirrorGroups[declaration.RemotePort] != nil {
			manager.mutex.Unlock()
			return rejectedSyncResult(
				request.Revision,
				ErrorMirrorMemberNotAllowed,
				declaration.Name,
				"mirror group membership is not allowed",
			)
		}
		if endpoint == nil {
			continue
		}
		currentBinding := manager.udpEndpointBindings[declaration.RemotePort]
		if currentBinding == nil || currentBinding.clientID != clientID ||
			existingUDPProxies[currentBinding.declaration.Name] != currentBinding {
			manager.mutex.Unlock()
			return rejectedSyncResult(
				request.Revision,
				ErrorPortConflict,
				declaration.Name,
				"UDP remote port is unavailable",
			)
		}
		reusableUDPEndpoints[declaration.RemotePort] = endpoint
	}
	manager.mutex.Unlock()
	manager.registrationMutex.Unlock()
	registrationLocked = false

	newEndpoints, newUDPEndpoints, preparationRejection :=
		manager.prepareSyncEndpoints(
			request,
			reusableEndpoints,
			reusableUDPEndpoints,
		)
	if preparationRejection != nil {
		return *preparationRejection
	}

	nextProxies := make(map[string]*tcpProxyBinding, len(request.Proxies))
	nextUDPProxies := make(map[string]*udpProxyBinding, len(request.Proxies))
	nextHTTPProxies := make(map[string]*httpProxyBinding, len(request.Proxies))
	results := make([]protocol.ProxyResult, 0, len(request.Proxies))
	for _, declaration := range request.Proxies {
		if declaration.Type != protocol.ProxyTypeTCP {
			continue
		}
		existing := existingProxies[declaration.Name]
		unchanged := existing != nil &&
			sameProxyDeclaration(existing.declaration, declaration)
		if unchanged && existing.sessionID == sessionID {
			nextProxies[declaration.Name] = existing
			results = append(results, protocol.ProxyResult{
				Name:       declaration.Name,
				Status:     protocol.ProxyStatusUnchanged,
				RemotePort: declaration.RemotePort,
			})
			continue
		}
		endpoint := reusableEndpoints[declaration.RemotePort]
		if endpoint == nil {
			endpoint = newEndpoints[declaration.RemotePort]
		}
		bindingID, err := newBindingID()
		if err != nil {
			closeTCPEndpoints(newEndpoints)
			closeUDPEndpoints(newUDPEndpoints)
			return rejectedSyncResult(
				request.Revision,
				ErrorInvalidRequest,
				declaration.Name,
				"generate proxy binding ID",
			)
		}
		nextProxies[declaration.Name] = &tcpProxyBinding{
			clientID:    clientID,
			sessionID:   sessionID,
			bindingID:   bindingID,
			declaration: declaration,
			endpoint:    endpoint,
		}
		status := protocol.ProxyStatusActive
		if unchanged {
			status = protocol.ProxyStatusUnchanged
		}
		results = append(results, protocol.ProxyResult{
			Name:       declaration.Name,
			Status:     status,
			RemotePort: declaration.RemotePort,
		})
	}
	for _, declaration := range request.Proxies {
		if declaration.Type != protocol.ProxyTypeUDP {
			continue
		}
		existing := existingUDPProxies[declaration.Name]
		unchanged := existing != nil &&
			sameProxyDeclaration(existing.declaration, declaration) &&
			existing.sessionID == sessionID
		if unchanged {
			nextUDPProxies[declaration.Name] = existing
			results = append(results, protocol.ProxyResult{
				Name:       declaration.Name,
				Status:     protocol.ProxyStatusUnchanged,
				RemotePort: declaration.RemotePort,
			})
			continue
		}
		endpoint := reusableUDPEndpoints[declaration.RemotePort]
		if endpoint == nil {
			endpoint = newUDPEndpoints[declaration.RemotePort]
		}
		binding, err := manager.newUDPBinding(
			clientID,
			sessionID,
			declaration,
			endpoint,
		)
		if err != nil {
			closeTCPEndpoints(newEndpoints)
			closeUDPEndpoints(newUDPEndpoints)
			closeUDPBindings(nextUDPProxies, existingUDPProxies)
			return rejectedSyncResult(
				request.Revision,
				ErrorInvalidRequest,
				declaration.Name,
				"create UDP proxy binding",
			)
		}
		nextUDPProxies[declaration.Name] = binding
		manager.mutex.Lock()
		if group := manager.mirrorGroupLocked(clientID, manager.clients[clientID], declaration); group != nil {
			binding.runtime.SetResponseEnabled(clientID == group.configuration.PrimaryClientID)
		}
		manager.mutex.Unlock()
		results = append(results, protocol.ProxyResult{
			Name:       declaration.Name,
			Status:     protocol.ProxyStatusActive,
			RemotePort: declaration.RemotePort,
		})
	}

	manager.mutex.Lock()
	for _, declaration := range request.Proxies {
		if declaration.Type != protocol.ProxyTypeHTTP {
			continue
		}
		owner := manager.httpDomains[declaration.Domain]
		if owner != nil && existingHTTPProxies[owner.declaration.Name] != owner {
			manager.mutex.Unlock()
			closeTCPEndpoints(newEndpoints)
			closeUDPEndpoints(newUDPEndpoints)
			closeUDPBindings(nextUDPProxies, existingUDPProxies)
			return rejectedSyncResult(request.Revision, ErrorDomainConflict, declaration.Name, "HTTP domain is unavailable")
		}
	}
	manager.mutex.Unlock()

	for _, declaration := range request.Proxies {
		if declaration.Type != protocol.ProxyTypeHTTP {
			continue
		}
		existing := existingHTTPProxies[declaration.Name]
		unchanged := existing != nil &&
			sameProxyDeclaration(existing.declaration, declaration) &&
			existing.sessionID == sessionID
		if unchanged {
			nextHTTPProxies[declaration.Name] = existing
			results = append(results, protocol.ProxyResult{
				Name: declaration.Name, Status: protocol.ProxyStatusUnchanged, Domain: declaration.Domain,
			})
			continue
		}
		binding, err := manager.newHTTPBinding(clientID, sessionID, declaration)
		if err != nil {
			closeTCPEndpoints(newEndpoints)
			closeUDPEndpoints(newUDPEndpoints)
			closeUDPBindings(nextUDPProxies, existingUDPProxies)
			closeHTTPBindings(nextHTTPProxies, existingHTTPProxies)
			return rejectedSyncResult(request.Revision, ErrorInvalidRequest, declaration.Name, "create HTTP proxy binding")
		}
		nextHTTPProxies[declaration.Name] = binding
		results = append(results, protocol.ProxyResult{
			Name: declaration.Name, Status: protocol.ProxyStatusActive, Domain: declaration.Domain,
		})
	}

	return manager.commitSync(syncCommitPreparation{
		clientID: clientID, sessionID: sessionID, requestID: requestID,
		request: request, fingerprint: fingerprint, baseRevision: baseRevision,
		authenticationMode: authenticationMode, results: results,
		existingProxies: existingProxies, existingUDPProxies: existingUDPProxies,
		existingHTTPProxies: existingHTTPProxies,
		reusableEndpoints:   reusableEndpoints, reusableUDPEndpoints: reusableUDPEndpoints,
		newEndpoints: newEndpoints, newUDPEndpoints: newUDPEndpoints,
		nextProxies: nextProxies, nextUDPProxies: nextUDPProxies,
		nextHTTPProxies:       nextHTTPProxies,
		declarationsByPort:    declarationsByPort,
		declarationsByUDPPort: declarationsByUDPPort,
	})
}
