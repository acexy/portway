package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
)

func (manager *tcpProxyManager) newHTTPBinding(
	clientID string,
	sessionID string,
	declaration protocol.ProxyDeclaration,
) (*httpProxyBinding, error) {
	bindingID, err := newBindingID()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(manager.context)
	binding := &httpProxyBinding{
		manager:     manager,
		clientID:    clientID,
		sessionID:   sessionID,
		bindingID:   bindingID,
		declaration: declaration,
		context:     ctx,
		cancel:      cancel,
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	binding.transport = &http.Transport{
		Protocols:               protocols,
		MaxIdleConns:            manager.httpConfiguration.MaxIdleConnections,
		MaxIdleConnsPerHost:     manager.httpConfiguration.MaxIdleConnectionsPerDomain,
		MaxResponseHeaderBytes:  int64(manager.httpConfiguration.MaxHeaderBytes),
		IdleConnTimeout:         manager.httpConfiguration.IdleConnectionTimeout,
		ResponseHeaderTimeout:   manager.httpConfiguration.ResponseHeaderTimeout,
		ExpectContinueTimeout:   0,
		DialContext:             binding.dialContext,
	}
	binding.proxy = &httputil.ReverseProxy{
		Transport: binding.transport,
		Rewrite: func(request *httputil.ProxyRequest) {
			request.Out.URL.Scheme = "http"
			request.Out.URL.Host = declaration.Domain
			request.Out.Host = request.In.Host
		},
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(writer, "Bad Gateway", http.StatusBadGateway)
		},
	}
	return binding, nil
}

func (binding *httpProxyBinding) dialContext(
	ctx context.Context,
	_ string,
	_ string,
) (net.Conn, error) {
	binding.manager.mutex.Lock()
	state := binding.manager.clients[binding.clientID]
	if state == nil || !state.active || state.sessionID != binding.sessionID ||
		state.httpProxies[binding.declaration.Name] != binding ||
		state.writer == nil {
		binding.manager.mutex.Unlock()
		return nil, errors.New("HTTP proxy binding is inactive")
	}
	target := linkTarget{
		clientID:  binding.clientID,
		sessionID: binding.sessionID,
		proxyName: binding.declaration.Name,
		proxyType: protocol.ProxyTypeHTTP,
		bindingID: binding.bindingID,
		writer:    state.writer,
	}
	binding.manager.mutex.Unlock()
	return binding.manager.linkBroker.openStream(ctx, target)
}

func (binding *httpProxyBinding) close() {
	binding.cancel()
	binding.transport.CloseIdleConnections()
	binding.manager.linkBroker.cancelBinding(binding.bindingID)
}

func closeHTTPBindings(
	bindings map[string]*httpProxyBinding,
	exclusions map[string]*httpProxyBinding,
) {
	for name, binding := range bindings {
		if exclusions[name] != binding {
			binding.close()
		}
	}
}

func (manager *tcpProxyManager) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method == http.MethodConnect {
		http.Error(writer, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	domain, err := normalizeRequestHost(request.Host)
	if err != nil {
		http.Error(writer, "Bad Request", http.StatusBadRequest)
		return
	}

	manager.mutex.Lock()
	binding := manager.httpDomains[domain]
	if binding == nil {
		manager.mutex.Unlock()
		http.Error(writer, "Misdirected Request", http.StatusMisdirectedRequest)
		return
	}
	state := manager.clients[binding.clientID]
	if state == nil || !state.active || state.sessionID != binding.sessionID ||
		state.httpProxies[binding.declaration.Name] != binding {
		manager.mutex.Unlock()
		http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	clientActive := 0
	clientUpgrades := 0
	for _, candidate := range state.httpProxies {
		clientActive += candidate.active
		clientUpgrades += candidate.activeUpgrades
	}
	upgrade := isUpgradeRequest(request)
	if manager.httpActiveRequests >= manager.httpConfiguration.MaxConcurrentRequests ||
		clientActive >= manager.httpConfiguration.MaxConcurrentRequestsPerClient ||
		binding.active >= manager.httpConfiguration.MaxConcurrentRequestsPerDomain ||
		(request.ProtoMajor == 2 &&
			binding.activeHTTP2 >= manager.httpConfiguration.MaxConcurrentHTTP2Streams) ||
		(upgrade && (manager.httpActiveUpgrades >= manager.httpConfiguration.MaxUpgradeConnections ||
			clientUpgrades >= manager.httpConfiguration.MaxUpgradeConnectionsPerClient ||
			binding.activeUpgrades >= manager.httpConfiguration.MaxUpgradeConnectionsPerDomain)) {
		manager.mutex.Unlock()
		http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	manager.httpActiveRequests++
	binding.active++
	if upgrade {
		manager.httpActiveUpgrades++
		binding.activeUpgrades++
	}
	if request.ProtoMajor == 2 {
		binding.activeHTTP2++
	}
	manager.mutex.Unlock()
	defer func() {
		manager.mutex.Lock()
		manager.httpActiveRequests--
		binding.active--
		if upgrade {
			manager.httpActiveUpgrades--
			binding.activeUpgrades--
		}
		if request.ProtoMajor == 2 {
			binding.activeHTTP2--
		}
		manager.mutex.Unlock()
	}()

	requestContext, cancelRequest := context.WithCancel(request.Context())
	stopBindingCancel := context.AfterFunc(binding.context, cancelRequest)
	defer stopBindingCancel()
	defer cancelRequest()
	binding.proxy.ServeHTTP(writer, request.WithContext(requestContext))
}

func isUpgradeRequest(request *http.Request) bool {
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

func normalizeRequestHost(host string) (string, error) {
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
