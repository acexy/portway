package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"sync"

	"github.com/acexy/portway/internal/consts"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
)

var tcpProxyNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

type tcpProxyManager struct {
	logger              *logging.Logger
	proxyBindIP         string
	context             context.Context
	linkBroker          *linkBroker
	mutex               sync.Mutex
	registrationMutex   sync.Mutex
	clients             map[string]*clientTCPProxyState
	endpoints           map[uint16]*tcpEndpointRuntime
	httpEnabled         bool
	httpConfiguration   config.HTTPConfig
	httpDomains         map[string]*httpProxyBinding
	httpActiveRequests  int
	httpActiveUpgrades  int
	listenerWaitGroup   sync.WaitGroup
	closed              bool
}

type clientTCPProxyState struct {
	sessionID       string
	active          bool
	writer          *controlWriter
	revision        uint64
	fingerprint     [sha256.Size]byte
	lastRequestID   string
	lastResult      protocol.SyncResult
	proxies         map[string]*tcpProxyBinding
	httpProxies     map[string]*httpProxyBinding
}

type tcpProxyBinding struct {
	clientID    string
	sessionID   string
	bindingID   string
	declaration protocol.ProxyDeclaration
	endpoint    *tcpEndpointRuntime
}

type tcpEndpointRuntime struct {
	manager     *tcpProxyManager
	remotePort  uint16
	listener    net.Listener
	binding     *tcpProxyBinding
	closeOnce   sync.Once
	startOnce   sync.Once
}

type httpProxyBinding struct {
	manager     *tcpProxyManager
	clientID    string
	sessionID   string
	bindingID   string
	declaration protocol.ProxyDeclaration
	context     context.Context
	cancel      context.CancelFunc
	transport   *http.Transport
	proxy       *httputil.ReverseProxy
	active      int
	activeUpgrades int
	activeHTTP2 int
}

func newTCPProxyManager(
	ctx context.Context,
	logger *logging.Logger,
	proxyBindIP string,
	broker *linkBroker,
	httpEnabled bool,
	httpConfiguration config.HTTPConfig,
) *tcpProxyManager {
	return &tcpProxyManager{
		logger:        logger,
		proxyBindIP:   proxyBindIP,
		context:       ctx,
		linkBroker:    broker,
		httpEnabled:   httpEnabled,
		httpConfiguration: httpConfiguration,
		httpDomains:   make(map[string]*httpProxyBinding),
		clients:       make(map[string]*clientTCPProxyState),
		endpoints:     make(map[uint16]*tcpEndpointRuntime),
	}
}

func (manager *tcpProxyManager) attach(
	clientID string,
	sessionID string,
	writer *controlWriter,
) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	state, exists := manager.clients[clientID]
	if !exists {
		state = &clientTCPProxyState{
			proxies: make(map[string]*tcpProxyBinding),
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

func (manager *tcpProxyManager) syncProxies(
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
	if len(request.Proxies) > consts.ServerMaxTCPProxiesPerClient {
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorCapacityExceeded,
			"",
			"TCP proxy limit exceeded",
		)
	}
	existingProxies := make(map[string]*tcpProxyBinding, len(state.proxies))
	for name, binding := range state.proxies {
		existingProxies[name] = binding
	}
	existingHTTPProxies := make(map[string]*httpProxyBinding, len(state.httpProxies))
	for name, binding := range state.httpProxies {
		existingHTTPProxies[name] = binding
	}
	manager.mutex.Unlock()

	declarationsByName := make(map[string]protocol.ProxyDeclaration, len(request.Proxies))
	declarationsByPort := make(map[uint16]protocol.ProxyDeclaration, len(request.Proxies))
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
		declarationsByName[declaration.Name] = declaration
	}

	manager.mutex.Lock()
	reusableEndpoints := make(map[uint16]*tcpEndpointRuntime, len(request.Proxies))
	for _, declaration := range request.Proxies {
		if declaration.Type != protocol.ProxyTypeTCP {
			continue
		}
		endpoint := manager.endpoints[declaration.RemotePort]
		if endpoint == nil {
			continue
		}
		currentBinding := endpoint.binding
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

	newEndpoints := make(map[uint16]*tcpEndpointRuntime)
	for _, declaration := range request.Proxies {
		if declaration.Type != protocol.ProxyTypeTCP {
			continue
		}
		if reusableEndpoints[declaration.RemotePort] != nil {
			continue
		}
		listenAddress := net.JoinHostPort(manager.proxyBindIP, strconv.Itoa(int(declaration.RemotePort)))
		listener, err := (&net.ListenConfig{}).Listen(manager.context, "tcp", listenAddress)
		if err != nil {
			closeTCPEndpoints(newEndpoints)
			return rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorPortConflict,
				declaration.Name,
				"remote port is unavailable",
			)
		}
		newEndpoints[declaration.RemotePort] = &tcpEndpointRuntime{
			manager:    manager,
			remotePort: declaration.RemotePort,
			listener:   listener,
		}
	}

	nextProxies := make(map[string]*tcpProxyBinding, len(request.Proxies))
	nextHTTPProxies := make(map[string]*httpProxyBinding, len(request.Proxies))
	results := make([]protocol.ProxyResult, 0, len(request.Proxies))
	for _, declaration := range request.Proxies {
		if declaration.Type == protocol.ProxyTypeHTTP {
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

	manager.mutex.Lock()
	for _, declaration := range request.Proxies {
		if declaration.Type != protocol.ProxyTypeHTTP {
			continue
		}
		owner := manager.httpDomains[declaration.Domain]
		if owner != nil && existingHTTPProxies[owner.declaration.Name] != owner {
			manager.mutex.Unlock()
			closeTCPEndpoints(newEndpoints)
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
			endpoint.binding == nil ||
			endpoint.binding.clientID != clientID ||
			existingProxies[endpoint.binding.declaration.Name] != endpoint.binding {
			manager.mutex.Unlock()
			closeTCPEndpoints(newEndpoints)
			return rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorPortConflict,
				declarationsByPort[port].Name,
				"remote port ownership changed during registration",
			)
		}
	}
	for _, binding := range nextHTTPProxies {
		owner := manager.httpDomains[binding.declaration.Domain]
		if owner != nil && existingHTTPProxies[owner.declaration.Name] != owner {
			manager.mutex.Unlock()
			closeTCPEndpoints(newEndpoints)
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
	removedHTTPBindings := make([]*httpProxyBinding, 0)
	for name, existing := range existingHTTPProxies {
		if nextHTTPProxies[name] != existing {
			removedHTTPBindings = append(removedHTTPBindings, existing)
			if manager.httpDomains[existing.declaration.Domain] == existing {
				delete(manager.httpDomains, existing.declaration.Domain)
			}
		}
	}
	nextEndpoints := make(map[uint16]*tcpEndpointRuntime, len(request.Proxies))
	for _, binding := range nextProxies {
		binding.sessionID = sessionID
		binding.endpoint.binding = binding
		nextEndpoints[binding.declaration.RemotePort] = binding.endpoint
		manager.endpoints[binding.declaration.RemotePort] = binding.endpoint
	}
	removedEndpoints := make(map[uint16]*tcpEndpointRuntime)
	for _, existing := range existingProxies {
		endpoint := existing.endpoint
		if nextEndpoints[endpoint.remotePort] != endpoint {
			if manager.endpoints[endpoint.remotePort] == endpoint {
				delete(manager.endpoints, endpoint.remotePort)
			}
			endpoint.binding = nil
			removedEndpoints[endpoint.remotePort] = endpoint
		}
	}
	state.proxies = nextProxies
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
		endpoint.start()
	}
	closeTCPEndpoints(removedEndpoints)
	for _, name := range removedProxyNames {
		manager.linkBroker.cancelBinding(existingProxies[name].bindingID)
	}
	for _, binding := range removedHTTPBindings {
		binding.close()
	}
	return result
}

func (manager *tcpProxyManager) activate(clientID string, sessionID string) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		return
	}
	state.active = true
}

func (manager *tcpProxyManager) suspend(clientID string, sessionID string) {
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

	manager.linkBroker.cancelSession(clientID, sessionID)
	for _, binding := range httpBindings {
		binding.transport.CloseIdleConnections()
	}
}

func (manager *tcpProxyManager) remove(clientID string, sessionID string) {
	manager.registrationMutex.Lock()
	defer manager.registrationMutex.Unlock()

	manager.mutex.Lock()
	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		manager.mutex.Unlock()
		return
	}
	delete(manager.clients, clientID)
	endpoints := make(map[uint16]*tcpEndpointRuntime, len(state.proxies))
	for _, binding := range state.proxies {
		endpoint := binding.endpoint
		if manager.endpoints[endpoint.remotePort] == endpoint {
			delete(manager.endpoints, endpoint.remotePort)
		}
		if endpoint.binding == binding {
			endpoint.binding = nil
		}
		endpoints[endpoint.remotePort] = endpoint
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
	manager.linkBroker.cancelSession(clientID, sessionID)
	for _, binding := range httpBindings {
		binding.close()
	}
}

func (manager *tcpProxyManager) close() {
	manager.registrationMutex.Lock()
	defer manager.registrationMutex.Unlock()

	manager.mutex.Lock()
	manager.closed = true
	endpoints := make(map[uint16]*tcpEndpointRuntime, len(manager.endpoints))
	httpBindings := make([]*httpProxyBinding, 0, len(manager.httpDomains))
	for port, endpoint := range manager.endpoints {
		endpoint.binding = nil
		endpoints[port] = endpoint
	}
	for _, binding := range manager.httpDomains {
		httpBindings = append(httpBindings, binding)
	}
	manager.clients = make(map[string]*clientTCPProxyState)
	manager.endpoints = make(map[uint16]*tcpEndpointRuntime)
	manager.httpDomains = make(map[string]*httpProxyBinding)
	manager.mutex.Unlock()

	closeTCPEndpoints(endpoints)
	for _, binding := range httpBindings {
		binding.close()
	}
	manager.listenerWaitGroup.Wait()
}

func (runtime *tcpEndpointRuntime) start() {
	runtime.startOnce.Do(func() {
		runtime.manager.listenerWaitGroup.Add(1)
		go func() {
			defer runtime.manager.listenerWaitGroup.Done()
			for {
				runtime.manager.mutex.Lock()
				binding := runtime.binding
				runtime.manager.mutex.Unlock()
				if binding == nil {
					return
				}
				visitor, err := runtime.listener.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) || runtime.manager.context.Err() != nil {
						return
					}
					runtime.manager.logger.Error("TCP proxy listener failed", err)
					return
				}
				runtime.manager.openVisitor(runtime, binding, visitor)
			}
		}()
	})
}

func (runtime *tcpEndpointRuntime) close() {
	runtime.closeOnce.Do(func() {
		runtime.listener.Close()
	})
}

func (manager *tcpProxyManager) openVisitor(
	endpoint *tcpEndpointRuntime,
	binding *tcpProxyBinding,
	visitor net.Conn,
) {
	manager.mutex.Lock()
	state, exists := manager.clients[binding.clientID]
	if manager.closed ||
		!exists ||
		!state.active ||
		state.sessionID != binding.sessionID ||
		endpoint.binding != binding ||
		state.proxies[binding.declaration.Name] != binding ||
		state.writer == nil {
		manager.mutex.Unlock()
		visitor.Close()
		return
	}
	writer := state.writer
	sessionID := state.sessionID
	manager.mutex.Unlock()

	err := manager.linkBroker.serveStream(
		linkTarget{
			clientID:  binding.clientID,
			sessionID: sessionID,
			proxyName: binding.declaration.Name,
			proxyType: protocol.ProxyTypeTCP,
			bindingID: binding.bindingID,
			writer:    writer,
		},
		func() { visitor.Close() },
		func(ctx context.Context, stream net.Conn) error {
			return proxytcp.Forward(ctx, visitor, stream)
		},
	)
	if err != nil {
		visitor.Close()
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
			Retryable: false,
		},
	}
}

func closeTCPEndpoints(endpoints map[uint16]*tcpEndpointRuntime) {
	for _, endpoint := range endpoints {
		endpoint.close()
	}
}
