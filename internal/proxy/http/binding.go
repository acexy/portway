// Package http implements HTTP reverse-proxy runtime behavior.
package http

import (
	"context"
	"errors"
	"net"
	stdhttp "net/http"
	"net/http/httputil"
	"strings"
	"sync"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/link"
)

// TargetResolver returns the current authenticated link target.
type TargetResolver func() (link.Target, error)

// Binding owns one HTTP reverse proxy, its connection pool, and local limits.
type Binding struct {
	bindingID      string
	domain         string
	context        context.Context
	cancel         context.CancelFunc
	broker         *link.Broker
	resolve        TargetResolver
	transport      *stdhttp.Transport
	proxy          *httputil.ReverseProxy
	mutex          sync.Mutex
	activeRequests int
	activeUpgrades int
	activeHTTP2    int
}

// NewBinding creates an HTTP runtime binding.
func NewBinding(
	parent context.Context,
	configuration config.HTTPConfig,
	bindingID string,
	domain string,
	broker *link.Broker,
	resolve TargetResolver,
) *Binding {
	ctx, cancel := context.WithCancel(parent)
	binding := &Binding{
		bindingID: bindingID,
		domain:    domain,
		context:   ctx,
		cancel:    cancel,
		broker:    broker,
		resolve:   resolve,
	}
	protocols := new(stdhttp.Protocols)
	protocols.SetHTTP1(true)
	binding.transport = &stdhttp.Transport{
		Protocols:              protocols,
		MaxIdleConns:           configuration.MaxIdleConnections,
		MaxIdleConnsPerHost:    configuration.MaxIdleConnectionsPerDomain,
		MaxResponseHeaderBytes: int64(configuration.MaxHeaderBytes),
		IdleConnTimeout:        configuration.IdleConnectionTimeout,
		ResponseHeaderTimeout:  configuration.ResponseHeaderTimeout,
		ExpectContinueTimeout:  0,
		DialContext:            binding.dialContext,
	}
	binding.proxy = &httputil.ReverseProxy{
		Transport: binding.transport,
		Rewrite: func(request *httputil.ProxyRequest) {
			request.Out.Header.Del("Forwarded")
			request.Out.Header.Del("X-Forwarded-For")
			request.Out.Header.Del("X-Forwarded-Host")
			request.Out.Header.Del("X-Forwarded-Proto")
			request.SetXForwarded()
			request.Out.URL.Scheme = "http"
			request.Out.URL.Host = domain
			request.Out.Host = request.In.Host
		},
		ErrorHandler: func(writer stdhttp.ResponseWriter, _ *stdhttp.Request, _ error) {
			stdhttp.Error(writer, "Bad Gateway", stdhttp.StatusBadGateway)
		},
	}
	return binding
}

func (binding *Binding) dialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	target, err := binding.resolve()
	if err != nil {
		return nil, err
	}
	return binding.broker.OpenStream(ctx, target)
}

// ID returns the immutable binding identifier.
func (binding *Binding) ID() string {
	return binding.bindingID
}

// CloseIdleConnections closes pooled idle backend links.
func (binding *Binding) CloseIdleConnections() {
	binding.transport.CloseIdleConnections()
}

// Close terminates the binding and all links owned by it.
func (binding *Binding) Close() {
	binding.cancel()
	binding.transport.CloseIdleConnections()
	binding.broker.CancelBinding(binding.bindingID)
}

// Active returns the current request and Upgrade counts.
func (binding *Binding) Active() (requests int, upgrades int) {
	binding.mutex.Lock()
	defer binding.mutex.Unlock()
	return binding.activeRequests, binding.activeUpgrades
}

// Acquire reserves this binding's request capacity.
func (binding *Binding) Acquire(
	upgrade bool,
	http2 bool,
	configuration config.HTTPConfig,
) bool {
	binding.mutex.Lock()
	defer binding.mutex.Unlock()
	if binding.activeRequests >= configuration.MaxConcurrentRequestsPerDomain ||
		(http2 && binding.activeHTTP2 >= configuration.MaxConcurrentHTTP2Streams) ||
		(upgrade && binding.activeUpgrades >= configuration.MaxUpgradeConnectionsPerDomain) {
		return false
	}
	binding.activeRequests++
	if upgrade {
		binding.activeUpgrades++
	}
	if http2 {
		binding.activeHTTP2++
	}
	return true
}

// Release returns capacity reserved by Acquire.
func (binding *Binding) Release(upgrade bool, http2 bool) {
	binding.mutex.Lock()
	binding.activeRequests--
	if upgrade {
		binding.activeUpgrades--
	}
	if http2 {
		binding.activeHTTP2--
	}
	binding.mutex.Unlock()
}

// ServeHTTP forwards one request and binds its cancellation to this runtime.
func (binding *Binding) ServeHTTP(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	requestContext, cancelRequest := context.WithCancel(request.Context())
	stopBindingCancel := context.AfterFunc(binding.context, cancelRequest)
	defer stopBindingCancel()
	defer cancelRequest()
	binding.proxy.ServeHTTP(writer, request.WithContext(requestContext))
}

// IsUpgradeRequest reports whether a request asks for an HTTP/1.1 Upgrade.
func IsUpgradeRequest(request *stdhttp.Request) bool {
	if request.Header.Get("Upgrade") == "" {
		return false
	}
	for _, value := range request.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

// NormalizeRequestHost validates and canonicalizes a routing Host.
func NormalizeRequestHost(host string) (string, error) {
	if host == "" {
		return "", errors.New("Host is required")
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	} else if strings.Contains(host, ":") {
		return "", errors.New("Host contains an invalid port")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if err := config.ValidateHTTPDomain(host); err != nil {
		return "", err
	}
	return host, nil
}
