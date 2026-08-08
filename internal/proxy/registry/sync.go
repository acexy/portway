package registry

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net"
	"strconv"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
)

func (manager *Registry) Sync(
	clientID string,
	sessionID string,
	requestID string,
	request protocol.SyncProxies,
) protocol.SyncResult {
	manager.registrationMutex.Lock()
	defer manager.registrationMutex.Unlock()

	if requestID == "" {
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorInvalidRequest,
			"",
			"request ID is required",
		)
	}
	fingerprintBytes, err := json.Marshal(request.Proxies)
	if err != nil {
		return rejectedSyncResult(request.Revision, protocol.ProxyErrorInvalidRequest, "", "encode proxy declaration")
	}
	fingerprint := sha256.Sum256(fingerprintBytes)

	manager.mutex.Lock()
	if manager.closed {
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorSessionInactive,
			"",
			"proxy registry is closed",
		)
	}
	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorSessionInactive,
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
			protocol.ProxyErrorInvalidRequest,
			"",
			"proxy request ID payload changed",
		)
	}
	if request.Revision == 0 || request.Revision < state.revision {
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorInvalidRequest,
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
			protocol.ProxyErrorInvalidRequest,
			"",
			"proxy revision payload changed",
		)
	}
	if len(request.Proxies) > maxProxiesPerClient {
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorCapacityExceeded,
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
	manager.mutex.Unlock()

	if authenticationMode != authentication.ModeManaged && len(request.Proxies) == 0 {
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorInvalidProxy,
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
		if endpoint == nil {
			continue
		}
		currentBinding := manager.endpointBindings[declaration.RemotePort]
		if currentBinding == nil || currentBinding.clientID != clientID {
			manager.mutex.Unlock()
			return rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorPortConflict,
				declaration.Name,
				"remote port is unavailable",
			)
		}
		if existingProxies[currentBinding.declaration.Name] != currentBinding {
			manager.mutex.Unlock()
			return rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorPortConflict,
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
		if endpoint == nil {
			continue
		}
		currentBinding := manager.udpEndpointBindings[declaration.RemotePort]
		if currentBinding == nil || currentBinding.clientID != clientID ||
			existingUDPProxies[currentBinding.declaration.Name] != currentBinding {
			manager.mutex.Unlock()
			return rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorPortConflict,
				declaration.Name,
				"UDP remote port is unavailable",
			)
		}
		reusableUDPEndpoints[declaration.RemotePort] = endpoint
	}
	manager.mutex.Unlock()

	newEndpoints := make(map[uint16]*proxytcp.Endpoint)
	for _, declaration := range request.Proxies {
		if declaration.Type != protocol.ProxyTypeTCP {
			continue
		}
		if reusableEndpoints[declaration.RemotePort] != nil {
			continue
		}
		listenAddress := net.JoinHostPort(manager.proxyBindIP, strconv.Itoa(int(declaration.RemotePort)))
		endpoint, err := proxytcp.Listen(
			manager.context,
			manager.logger.WithComponent("proxy_tcp"),
			listenAddress,
			manager.sourceFilter,
		)
		if err != nil {
			closeTCPEndpoints(newEndpoints)
			return rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorPortConflict,
				declaration.Name,
				"remote port is unavailable",
			)
		}
		newEndpoints[declaration.RemotePort] = endpoint
	}
	newUDPEndpoints := make(map[uint16]*proxyudp.Endpoint)
	for _, declaration := range request.Proxies {
		if declaration.Type != protocol.ProxyTypeUDP ||
			reusableUDPEndpoints[declaration.RemotePort] != nil {
			continue
		}
		listenAddress := net.JoinHostPort(
			manager.proxyBindIP,
			strconv.Itoa(int(declaration.RemotePort)),
		)
		endpoint, err := proxyudp.Listen(
			manager.context,
			manager.logger.WithComponent("proxy_udp"),
			listenAddress,
			manager.sourceFilter,
			manager.udpConfiguration.MaxDatagramSize,
		)
		if err != nil {
			closeTCPEndpoints(newEndpoints)
			closeUDPEndpoints(newUDPEndpoints)
			return rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorPortConflict,
				declaration.Name,
				"UDP remote port is unavailable",
			)
		}
		newUDPEndpoints[declaration.RemotePort] = endpoint
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
				protocol.ProxyErrorInvalidRequest,
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
				protocol.ProxyErrorInvalidRequest,
				declaration.Name,
				"create UDP proxy binding",
			)
		}
		nextUDPProxies[declaration.Name] = binding
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
			return rejectedSyncResult(request.Revision, protocol.ProxyErrorDomainConflict, declaration.Name, "HTTP domain is unavailable")
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
			return rejectedSyncResult(request.Revision, protocol.ProxyErrorInvalidRequest, declaration.Name, "create HTTP proxy binding")
		}
		nextHTTPProxies[declaration.Name] = binding
		results = append(results, protocol.ProxyResult{
			Name: declaration.Name, Status: protocol.ProxyStatusActive, Domain: declaration.Domain,
		})
	}

	result := protocol.SyncResult{
		Revision: request.Revision,
		Status:   protocol.ProxySyncStatusApplied,
		Proxies:  results,
	}
	manager.mutex.Lock()
	state, exists = manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		manager.mutex.Unlock()
		closeTCPEndpoints(newEndpoints)
		closeUDPEndpoints(newUDPEndpoints)
		closeUDPBindings(nextUDPProxies, existingUDPProxies)
		closeHTTPBindings(nextHTTPProxies, existingHTTPProxies)
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorSessionInactive,
			"",
			"client session changed during registration",
		)
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

func (state *clientState) cacheSyncRequest(
	requestID string,
	revision uint64,
	fingerprint [sha256.Size]byte,
	result protocol.SyncResult,
) {
	if len(state.requestOrder) == maxCachedSyncRequests {
		oldest := state.requestOrder[0]
		state.requestOrder = state.requestOrder[1:]
		delete(state.requestCache, oldest)
	}
	state.requestOrder = append(state.requestOrder, requestID)
	state.requestCache[requestID] = cachedSyncRequest{
		revision: revision, fingerprint: fingerprint, result: result,
	}
}
func newBindingID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func rejectedSyncResult(
	revision uint64,
	code protocol.ProxyErrorCode,
	proxyName string,
	message string,
) protocol.SyncResult {
	return protocol.SyncResult{
		Revision: revision,
		Status:   protocol.ProxySyncStatusRejected,
		Proxies:  []protocol.ProxyResult{},
		Error: &protocol.ProxyError{
			Code:      code,
			Message:   message,
			ProxyName: proxyName,
			Retryable: code == protocol.ProxyErrorSessionInactive,
		},
	}
}
