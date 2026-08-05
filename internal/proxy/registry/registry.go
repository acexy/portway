// Package registry owns atomic proxy registration and resource bindings.
package registry

import (
	"context"
	"crypto/sha256"
	"slices"
	"sync"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	proxyhttp "github.com/acexy/portway/internal/proxy/http"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
	"github.com/acexy/portway/internal/security/ipfilter"
)

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
	managedTCPPorts     map[uint16]string
	managedUDPPorts     map[uint16]string
	managedHTTPDomains  map[string]string
	udpConfiguration    config.UDPConfig
	udpLimiter          *proxyudp.Limiter
	httpEnabled         bool
	httpsEnabled        bool
	httpConfiguration   config.HTTPConfig
	httpDomains         map[string]*httpProxyBinding
	httpActiveRequests  int
	httpActiveUpgrades  int
	sourceFilter        *ipfilter.Filter
	closed              bool
}

type clientState struct {
	sessionID          string
	active             bool
	writer             *control.Writer
	revision           uint64
	fingerprint        [sha256.Size]byte
	lastRequestID      string
	lastResult         protocol.SyncResult
	requestCache       map[string]cachedSyncRequest
	requestOrder       []string
	authentication     authentication.Context
	maxActiveLinks     int
	httpActiveRequests int
	httpActiveUpgrades int
	tcpProxies         map[string]*tcpProxyBinding
	udpProxies         map[string]*udpProxyBinding
	httpProxies        map[string]*httpProxyBinding
}

type cachedSyncRequest struct {
	revision    uint64
	fingerprint [sha256.Size]byte
	result      protocol.SyncResult
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

func sameProxyDeclaration(
	left protocol.ProxyDeclaration,
	right protocol.ProxyDeclaration,
) bool {
	return left.Name == right.Name &&
		left.Type == right.Type &&
		left.RemotePort == right.RemotePort &&
		left.Domain == right.Domain &&
		slices.Equal(left.PublicSchemes, right.PublicSchemes)
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
		false,
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
	httpsEnabled bool,
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
		httpsEnabled,
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
	httpsEnabled bool,
	httpConfiguration config.HTTPConfig,
	udpConfiguration config.UDPConfig,
	sourceFilters ...*ipfilter.Filter,
) *Registry {
	var sourceFilter *ipfilter.Filter
	if len(sourceFilters) > 0 {
		sourceFilter = sourceFilters[0]
	}
	return &Registry{
		logger:              logger,
		proxyBindIP:         proxyBindIP,
		context:             ctx,
		linkBroker:          broker,
		httpEnabled:         httpEnabled,
		httpsEnabled:        httpsEnabled,
		httpConfiguration:   httpConfiguration,
		udpConfiguration:    udpConfiguration,
		udpLimiter:          proxyudp.NewLimiter(udpConfiguration),
		sourceFilter:        sourceFilter,
		httpDomains:         make(map[string]*httpProxyBinding),
		clients:             make(map[string]*clientState),
		endpoints:           make(map[uint16]*proxytcp.Endpoint),
		endpointBindings:    make(map[uint16]*tcpProxyBinding),
		udpEndpoints:        make(map[uint16]*proxyudp.Endpoint),
		udpEndpointBindings: make(map[uint16]*udpProxyBinding),
		managedTCPPorts:     make(map[uint16]string),
		managedUDPPorts:     make(map[uint16]string),
		managedHTTPDomains:  make(map[string]string),
	}
}

func (manager *Registry) Attach(
	clientID string,
	sessionID string,
	writer *control.Writer,
) {
	manager.AttachAuthenticated(
		clientID,
		sessionID,
		writer,
		authentication.Context{Mode: authentication.ModeShared},
		0,
	)
}

// AttachAuthenticated binds proxy ownership to an authenticated Session.
func (manager *Registry) AttachAuthenticated(
	clientID string,
	sessionID string,
	writer *control.Writer,
	authenticationContext authentication.Context,
	maxActiveLinks int,
) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	state, exists := manager.clients[clientID]
	if !exists {
		state = &clientState{
			tcpProxies:  make(map[string]*tcpProxyBinding),
			udpProxies:  make(map[string]*udpProxyBinding),
			httpProxies: make(map[string]*httpProxyBinding),
			requestCache: make(map[string]cachedSyncRequest),
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
	state.requestCache = make(map[string]cachedSyncRequest)
	state.requestOrder = nil
	state.authentication = authenticationContext
	state.maxActiveLinks = maxActiveLinks
}
