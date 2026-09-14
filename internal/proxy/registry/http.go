package registry

import (
	"errors"
	"net/http"
	"time"

	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
	proxyhttp "github.com/acexy/portway/internal/proxy/http"
)

func (manager *Registry) newHTTPBinding(
	clientID string,
	sessionID string,
	declaration protocol.ProxyDeclaration,
) (*httpProxyBinding, error) {
	bindingID, err := newBindingID()
	if err != nil {
		return nil, err
	}
	binding := &httpProxyBinding{
		manager: manager, clientID: clientID, sessionID: sessionID,
		bindingID: bindingID, declaration: declaration,
	}
	binding.runtime = proxyhttp.NewBinding(
		manager.context,
		manager.httpConfiguration,
		bindingID,
		declaration.Domain,
		manager.linkBroker,
		manager.httpConnectionLimiter,
		binding.resolveTarget,
	)
	return binding, nil
}

func (binding *httpProxyBinding) resolveTarget() (link.Target, error) {
	binding.manager.mutex.Lock()
	defer binding.manager.mutex.Unlock()
	state := binding.manager.clients[binding.clientID]
	if state == nil || !state.active || state.sessionID != binding.sessionID ||
		state.httpProxies[binding.declaration.Name] != binding ||
		state.writer == nil {
		return link.Target{}, errors.New("HTTP proxy binding is inactive")
	}
	return link.Target{
		ClientID: binding.clientID, SessionID: binding.sessionID,
		ProxyName: binding.declaration.Name, ProxyType: protocol.ProxyTypeHTTP,
		BindingID: binding.bindingID, Writer: state.writer,
		Authentication: state.authentication,
		MaxActiveLinks: state.maxActiveLinks,
	}, nil
}

func (binding *httpProxyBinding) close() {
	binding.runtime.Close()
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

// ServeHTTP routes one public HTTP request to its registered binding.
func (manager *Registry) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	startedAt := time.Now()
	if request.Method == http.MethodConnect {
		manager.logHTTPRequest(request, "rejected", "method_not_allowed", "")
		http.Error(writer, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	domain, err := proxyhttp.NormalizeRequestHost(request.Host)
	if err != nil {
		manager.logHTTPRequest(request, "rejected", "invalid_host", "")
		http.Error(writer, "Bad Request", http.StatusBadRequest)
		return
	}
	if request.TLS != nil {
		serverName, serverNameError := proxyhttp.NormalizeRequestHost(request.TLS.ServerName)
		if serverNameError != nil || serverName != domain {
			manager.logHTTPRequest(request, "rejected", "sni_host_mismatch", domain)
			http.Error(writer, "Misdirected Request", http.StatusMisdirectedRequest)
			return
		}
	}
	upgrade := proxyhttp.IsUpgradeRequest(request)
	http2 := request.ProtoMajor == 2

	manager.mutex.Lock()
	binding := manager.httpDomains[domain]
	if binding == nil {
		manager.mutex.Unlock()
		manager.logHTTPRequest(request, "rejected", "domain_not_registered", domain)
		http.Error(writer, "Misdirected Request", http.StatusMisdirectedRequest)
		return
	}
	publicScheme := protocol.HTTPPublicScheme(requestScheme(request))
	if !binding.declaration.AllowsPublicScheme(publicScheme) {
		manager.mutex.Unlock()
		manager.logHTTPRequest(request, "rejected", "public_scheme_not_registered", domain)
		http.Error(writer, "Misdirected Request", http.StatusMisdirectedRequest)
		return
	}
	state := manager.clients[binding.clientID]
	if state == nil || !state.active || state.sessionID != binding.sessionID ||
		state.httpProxies[binding.declaration.Name] != binding {
		manager.mutex.Unlock()
		manager.logHTTPRequest(request, "rejected", "proxy_inactive", domain)
		http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	if manager.httpActiveRequests >= manager.httpConfiguration.MaxConcurrentRequests ||
		state.httpActiveRequests >= manager.httpConfiguration.MaxConcurrentRequestsPerClient ||
		(upgrade && (manager.httpActiveUpgrades >= manager.httpConfiguration.MaxUpgradeConnections ||
			state.httpActiveUpgrades >= manager.httpConfiguration.MaxUpgradeConnectionsPerClient)) ||
		!binding.runtime.Acquire(upgrade, http2, manager.httpConfiguration) {
		manager.mutex.Unlock()
		manager.logHTTPRequest(request, "rejected", "capacity_exceeded", domain)
		http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	manager.httpActiveRequests++
	state.httpActiveRequests++
	if upgrade {
		manager.httpActiveUpgrades++
		state.httpActiveUpgrades++
	}
	manager.mutex.Unlock()
	manager.logHTTPRequest(request, "accepted", "", domain)

	defer func() {
		binding.runtime.Release(upgrade, http2)
		manager.mutex.Lock()
		manager.httpActiveRequests--
		state.httpActiveRequests--
		if upgrade {
			manager.httpActiveUpgrades--
			state.httpActiveUpgrades--
		}
		manager.mutex.Unlock()
	}()
	requestResult := binding.runtime.ServeHTTPResult(writer, request)
	result := "completed"
	if requestResult.ErrorCode != "" {
		result = "failed"
	}
	fields := map[string]any{
		"event":          "http_request_completed",
		"client_id":      binding.clientID,
		"session_id":     binding.sessionID,
		"proxy_name":     binding.declaration.Name,
		"proxy_type":     protocol.ProxyTypeHTTP,
		"scheme":         requestScheme(request),
		"method":         request.Method,
		"host":           domain,
		"protocol":       request.Proto,
		"remote_address": request.RemoteAddr,
		"result":         result,
		"status_code":    requestResult.StatusCode,
		"duration_ms":    time.Since(startedAt).Milliseconds(),
	}
	if requestResult.ErrorCode != "" {
		fields["reason"] = requestResult.ErrorCode
		fields["error_code"] = requestResult.ErrorCode
	}
	if requestResult.Err != nil {
		fields["error"] = requestResult.Err
	}
	if requestResult.ErrorCode != "" {
		if count, emit := manager.httpFailureLogs.Record(time.Now()); emit {
			warningFields := make(map[string]any, len(fields)+1)
			for field, value := range fields {
				warningFields[field] = value
			}
			warningFields["failure_count"] = count
			manager.logger.WithComponent("proxy_http").WarnWithFields(
				"HTTP proxy request failed; additional failures are rate limited",
				requestResult.Err,
				warningFields,
			)
		}
	}
	manager.logger.WithComponent("proxy_http").DebugWithFields(
		"HTTP request completed",
		fields,
	)
}

func (manager *Registry) logHTTPRequest(
	request *http.Request,
	result string,
	reason string,
	domain string,
) {
	fields := map[string]any{
		"event":          "http_request_routed",
		"scheme":         requestScheme(request),
		"method":         request.Method,
		"host":           domain,
		"protocol":       request.Proto,
		"remote_address": request.RemoteAddr,
		"result":         result,
	}
	if reason != "" {
		fields["reason"] = reason
	}
	manager.logger.WithComponent("proxy_http").DebugWithFields(
		"HTTP request routed",
		fields,
	)
}

func requestScheme(request *http.Request) string {
	if request.TLS != nil {
		return "https"
	}
	return "http"
}
