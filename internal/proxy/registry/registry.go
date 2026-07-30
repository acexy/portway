// Package registry owns atomic proxy registration and resource bindings.
package registry

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"sync"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
	proxyhttp "github.com/acexy/portway/internal/proxy/http"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
	"github.com/acexy/portway/internal/security/ipfilter"
)

var tcpProxyNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Registry owns the complete proxy set and public routing resources.
type Registry struct {
	logger              *logging.Logger
	proxyBindIP         string
	context             context.Context
	linkBroker          *link.Broker
	mutex               sync.Mutex
	registrationMutex   sync.Mutex
	clients             map[string]*clientState
	endpoints           map[uint16]*proxytcp.Endpoint
	endpointBindings    map[uint16]*tcpProxyBinding
	udpEndpoints        map[uint16]*proxyudp.Endpoint
	udpEndpointBindings map[uint16]*udpProxyBinding
	udpConfiguration    config.UDPConfig
	udpLimiter          *proxyudp.Limiter
	httpEnabled         bool
	httpConfiguration   config.HTTPConfig
	httpDomains         map[string]*httpProxyBinding
	httpActiveRequests  int
	httpActiveUpgrades  int
	sourceFilter         *ipfilter.Filter
	closed              bool
}

type clientState struct {
	sessionID       string
	active          bool
	writer          *control.Writer
	revision        uint64
	fingerprint     [sha256.Size]byte
	lastRequestID   string
	lastResult      protocol.SyncResult
	tcpProxies      map[string]*tcpProxyBinding
	udpProxies      map[string]*udpProxyBinding
	httpProxies     map[string]*httpProxyBinding
}

type tcpProxyBinding struct {
	clientID    string
	sessionID   string
	bindingID   string
	declaration protocol.ProxyDeclaration
	endpoint    *proxytcp.Endpoint
}

type httpProxyBinding struct {
	manager     *Registry
	clientID    string
	sessionID   string
	bindingID   string
	declaration protocol.ProxyDeclaration
	runtime     *proxyhttp.Binding
}

type udpProxyBinding struct {
	manager     *Registry
	clientID    string
	sessionID   string
	bindingID   string
	declaration protocol.ProxyDeclaration
	endpoint    *proxyudp.Endpoint
	runtime     *proxyudp.Binding
}

// New creates a proxy registry.
func New(
	ctx context.Context,
	logger *logging.Logger,
	proxyBindIP string,
	broker *link.Broker,
	httpEnabled bool,
	httpConfiguration config.HTTPConfig,
	sourceFilters ...*ipfilter.Filter,
) *Registry {
	return newRegistry(
		ctx,
		logger,
		proxyBindIP,
		broker,
		httpEnabled,
		httpConfiguration,
		config.DefaultUDPConfig(),
		sourceFilters...,
	)
}

// NewConfigured creates a registry with explicit HTTP and UDP resource limits.
func NewConfigured(
	ctx context.Context,
	logger *logging.Logger,
	proxyBindIP string,
	broker *link.Broker,
	httpEnabled bool,
	httpConfiguration config.HTTPConfig,
	udpConfiguration config.UDPConfig,
	sourceFilters ...*ipfilter.Filter,
) *Registry {
	return newRegistry(
		ctx,
		logger,
		proxyBindIP,
		broker,
		httpEnabled,
		httpConfiguration,
		udpConfiguration,
		sourceFilters...,
	)
}

func newRegistry(
	ctx context.Context,
	logger *logging.Logger,
	proxyBindIP string,
	broker *link.Broker,
	httpEnabled bool,
	httpConfiguration config.HTTPConfig,
	udpConfiguration config.UDPConfig,
	sourceFilters ...*ipfilter.Filter,
) *Registry {
	var sourceFilter *ipfilter.Filter
	if len(sourceFilters) > 0 {
		sourceFilter = sourceFilters[0]
	}
	return &Registry{
		logger:        logger,
		proxyBindIP:   proxyBindIP,
		context:       ctx,
		linkBroker:    broker,
		httpEnabled:   httpEnabled,
		httpConfiguration: httpConfiguration,
		udpConfiguration: udpConfiguration,
		udpLimiter: proxyudp.NewLimiter(udpConfiguration),
		sourceFilter: sourceFilter,
		httpDomains:   make(map[string]*httpProxyBinding),
		clients:       make(map[string]*clientState),
		endpoints:     make(map[uint16]*proxytcp.Endpoint),
		endpointBindings: make(map[uint16]*tcpProxyBinding),
		udpEndpoints: make(map[uint16]*proxyudp.Endpoint),
		udpEndpointBindings: make(map[uint16]*udpProxyBinding),
	}
}

func (manager *Registry) Attach(
	clientID string,
	sessionID string,
	writer *control.Writer,
) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	state, exists := manager.clients[clientID]
	if !exists {
		state = &clientState{
			tcpProxies: make(map[string]*tcpProxyBinding),
			udpProxies: make(map[string]*udpProxyBinding),
			httpProxies: make(map[string]*httpProxyBinding),
		}
		manager.clients[clientID] = state
	}
	state.sessionID = sessionID
	state.active = false
	state.writer = writer
	state.revision = 0
	state.fingerprint = [sha256.Size]byte{}
	state.lastRequestID = ""
	state.lastResult = protocol.SyncResult{}
}

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
			"TCP proxy manager is closed",
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
	if requestID == state.lastRequestID {
		result := state.lastResult
		manager.mutex.Unlock()
		return result
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
			"TCP proxy limit exceeded",
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
	manager.mutex.Unlock()

	declarationsByName := make(map[string]protocol.ProxyDeclaration, len(request.Proxies))
	declarationsByPort := make(map[uint16]protocol.ProxyDeclaration, len(request.Proxies))
	declarationsByUDPPort := make(map[uint16]protocol.ProxyDeclaration, len(request.Proxies))
	for _, declaration := range request.Proxies {
		if !tcpProxyNamePattern.MatchString(declaration.Name) {
			return rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorInvalidProxy,
				declaration.Name,
				"invalid TCP proxy declaration",
			)
		}
		switch declaration.Type {
		case protocol.ProxyTypeTCP:
			if declaration.RemotePort == 0 || declaration.Domain != "" {
				return rejectedSyncResult(request.Revision, protocol.ProxyErrorInvalidProxy, declaration.Name, "invalid TCP proxy declaration")
			}
		case protocol.ProxyTypeUDP:
			if declaration.RemotePort == 0 || declaration.Domain != "" {
				return rejectedSyncResult(request.Revision, protocol.ProxyErrorInvalidProxy, declaration.Name, "invalid UDP proxy declaration")
			}
		case protocol.ProxyTypeHTTP:
			if declaration.RemotePort != 0 || config.ValidateHTTPDomain(declaration.Domain) != nil {
				return rejectedSyncResult(request.Revision, protocol.ProxyErrorInvalidProxy, declaration.Name, "invalid HTTP proxy declaration")
			}
			if !manager.httpEnabled {
				return rejectedSyncResult(request.Revision, protocol.ProxyErrorHTTPDisabled, declaration.Name, "HTTP listener is disabled")
			}
		default:
			return rejectedSyncResult(request.Revision, protocol.ProxyErrorInvalidProxy, declaration.Name, "unsupported proxy type")
		}
		if _, duplicate := declarationsByName[declaration.Name]; duplicate {
			return rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorInvalidProxy,
				declaration.Name,
				"duplicate proxy name",
			)
		}
		if declaration.Type == protocol.ProxyTypeTCP {
			if _, duplicate := declarationsByPort[declaration.RemotePort]; duplicate {
				return rejectedSyncResult(
					request.Revision,
					protocol.ProxyErrorInvalidProxy,
					declaration.Name,
					"duplicate remote port",
				)
			}
			declarationsByPort[declaration.RemotePort] = declaration
		}
		if declaration.Type == protocol.ProxyTypeUDP {
			if _, duplicate := declarationsByUDPPort[declaration.RemotePort]; duplicate {
				return rejectedSyncResult(
					request.Revision,
					protocol.ProxyErrorInvalidProxy,
					declaration.Name,
					"duplicate UDP remote port",
				)
			}
			declarationsByUDPPort[declaration.RemotePort] = declaration
		}
		declarationsByName[declaration.Name] = declaration
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
			manager.logger,
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
			manager.logger,
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
		unchanged := existing != nil && existing.declaration == declaration
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
		unchanged := existing != nil && existing.declaration == declaration &&
			existing.sessionID == sessionID
		if unchanged {
			nextUDPProxies[declaration.Name] = existing
			results = append(results, protocol.ProxyResult{
				Name: declaration.Name,
				Status: protocol.ProxyStatusUnchanged,
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
			Name: declaration.Name,
			Status: protocol.ProxyStatusActive,
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
		unchanged := existing != nil && existing.declaration == declaration &&
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
			Retryable: false,
		},
	}
}
