// Package http implements HTTP reverse-proxy runtime behavior.
package http

import (
	"context"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/security/ipfilter"
)

// TargetResolver returns the current authenticated link target.
type TargetResolver func() (link.Target, error)

// Binding owns one HTTP reverse proxy, its connection pool, and local limits.
type Binding struct {
	bindingID           string
	domain              string
	context             context.Context
	cancel              context.CancelFunc
	broker              *link.Broker
	connectionLimiter   *ConnectionLimiter
	resolve             TargetResolver
	transport           *stdhttp.Transport
	upgradeTransport    *stdhttp.Transport
	proxy               *httputil.ReverseProxy
	requestBodyTimeout  time.Duration
	maxRequestBodyBytes int64
	mutex               sync.Mutex
	activeRequests      int
	activeUpgrades      int
	activeHTTP2         int
}

// NewBinding creates an HTTP runtime binding.
func NewBinding(
	parent context.Context,
	configuration config.HTTPConfig,
	bindingID string,
	domain string,
	broker *link.Broker,
	connectionLimiter *ConnectionLimiter,
	resolve TargetResolver,
) *Binding {
	ctx, cancel := context.WithCancel(parent)
	binding := &Binding{
		bindingID:           bindingID,
		domain:              domain,
		context:             ctx,
		cancel:              cancel,
		broker:              broker,
		connectionLimiter:   connectionLimiter,
		resolve:             resolve,
		requestBodyTimeout:  configuration.RequestBodyTimeout,
		maxRequestBodyBytes: configuration.MaxRequestBodyBytes,
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
	binding.upgradeTransport = binding.transport.Clone()
	binding.upgradeTransport.DisableKeepAlives = true
	binding.upgradeTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := binding.dialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return newIdleTimeoutConnection(connection, configuration.UpgradeIdleTimeout), nil
	}
	binding.proxy = &httputil.ReverseProxy{
		Transport: routingTransport{
			regular: binding.transport,
			upgrade: binding.upgradeTransport,
		},
		Rewrite: func(request *httputil.ProxyRequest) {
			request.Out.Header.Del("Forwarded")
			request.Out.Header.Del("X-Forwarded-For")
			request.Out.Header.Del("X-Forwarded-Host")
			request.Out.Header.Del("X-Forwarded-Proto")
			request.SetXForwarded()
			if addresses := ipfilter.HTTPSourceAddresses(request.In); len(addresses) > 0 {
				parts := make([]string, len(addresses))
				for index, address := range addresses {
					parts[index] = address.String()
				}
				request.Out.Header.Set("X-Forwarded-For", strings.Join(parts, ", "))
			}
			request.Out.URL.Scheme = "http"
			request.Out.URL.Host = domain
			request.Out.Host = request.In.Host
		},
		ErrorHandler: func(writer stdhttp.ResponseWriter, request *stdhttp.Request, err error) {
			status := stdhttp.StatusBadGateway
			message := "Bad Gateway"
			var networkError net.Error
			var maximumBytesError *stdhttp.MaxBytesError
			if errors.Is(context.Cause(request.Context()), errRequestBodyTimeout) {
				status = stdhttp.StatusRequestTimeout
				message = "Request Timeout"
			} else if errors.As(err, &maximumBytesError) {
				status = stdhttp.StatusRequestEntityTooLarge
				message = "Request Entity Too Large"
			} else if errors.Is(err, context.DeadlineExceeded) ||
				(errors.As(err, &networkError) && networkError.Timeout()) {
				status = stdhttp.StatusGatewayTimeout
				message = "Gateway Timeout"
			}
			stdhttp.Error(writer, message, status)
		},
	}
	return binding
}

func (binding *Binding) dialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	target, err := binding.resolve()
	if err != nil {
		return nil, err
	}
	release, err := binding.connectionLimiter.acquire(ctx)
	if err != nil {
		return nil, err
	}
	connection, err := binding.broker.OpenStream(ctx, target)
	if err != nil {
		release()
		return nil, err
	}
	return &limitedConnection{Conn: connection, release: release}, nil
}

// ID returns the immutable binding identifier.
func (binding *Binding) ID() string {
	return binding.bindingID
}

// CloseIdleConnections closes pooled idle backend links.
func (binding *Binding) CloseIdleConnections() {
	binding.transport.CloseIdleConnections()
	binding.upgradeTransport.CloseIdleConnections()
}

// Close terminates the binding and all links owned by it.
func (binding *Binding) Close() {
	binding.cancel()
	binding.transport.CloseIdleConnections()
	binding.upgradeTransport.CloseIdleConnections()
	binding.broker.CancelBinding(binding.bindingID)
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
	if binding.maxRequestBodyBytes > 0 && request.ContentLength > binding.maxRequestBodyBytes {
		stdhttp.Error(writer, "Request Entity Too Large", stdhttp.StatusRequestEntityTooLarge)
		return
	}
	requestContext, cancelRequest := context.WithCancelCause(request.Context())
	stopBindingCancel := context.AfterFunc(binding.context, func() { cancelRequest(context.Canceled) })
	defer stopBindingCancel()
	defer cancelRequest(context.Canceled)
	if request.Body != nil {
		if binding.maxRequestBodyBytes > 0 {
			request.Body = stdhttp.MaxBytesReader(writer, request.Body, binding.maxRequestBodyBytes)
		}
		if binding.requestBodyTimeout > 0 {
			request.Body = newTimedRequestBody(request.Body, binding.requestBodyTimeout, cancelRequest)
		}
	}
	binding.proxy.ServeHTTP(writer, request.WithContext(requestContext))
}

var errRequestBodyTimeout = errors.New("request body timeout")

type routingTransport struct {
	regular stdhttp.RoundTripper
	upgrade stdhttp.RoundTripper
}

func (transport routingTransport) RoundTrip(request *stdhttp.Request) (*stdhttp.Response, error) {
	if IsUpgradeRequest(request) {
		return transport.upgrade.RoundTrip(request)
	}
	return transport.regular.RoundTrip(request)
}

type timedRequestBody struct {
	io.ReadCloser
	timer *time.Timer
	once  sync.Once
}

func newTimedRequestBody(
	body io.ReadCloser,
	timeout time.Duration,
	cancel context.CancelCauseFunc,
) io.ReadCloser {
	timedBody := &timedRequestBody{ReadCloser: body}
	timedBody.timer = time.AfterFunc(timeout, func() {
		timedBody.once.Do(func() {
			cancel(errRequestBodyTimeout)
			_ = body.Close()
		})
	})
	return timedBody
}

func (body *timedRequestBody) Read(buffer []byte) (int, error) {
	read, err := body.ReadCloser.Read(buffer)
	if errors.Is(err, io.EOF) {
		body.stopTimer()
	}
	return read, err
}

func (body *timedRequestBody) Close() error {
	body.stopTimer()
	return body.ReadCloser.Close()
}

func (body *timedRequestBody) stopTimer() {
	body.once.Do(func() { body.timer.Stop() })
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
