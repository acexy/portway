package registry

import (
	"errors"
	"net/http"

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
	if request.Method == http.MethodConnect {
		http.Error(writer, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	domain, err := proxyhttp.NormalizeRequestHost(request.Host)
	if err != nil {
		http.Error(writer, "Bad Request", http.StatusBadRequest)
		return
	}
	upgrade := proxyhttp.IsUpgradeRequest(request)
	http2 := request.ProtoMajor == 2

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
	clientActive, clientUpgrades := 0, 0
	for _, candidate := range state.httpProxies {
		active, upgrades := candidate.runtime.Active()
		clientActive += active
		clientUpgrades += upgrades
	}
	if manager.httpActiveRequests >= manager.httpConfiguration.MaxConcurrentRequests ||
		clientActive >= manager.httpConfiguration.MaxConcurrentRequestsPerClient ||
		(upgrade && (manager.httpActiveUpgrades >= manager.httpConfiguration.MaxUpgradeConnections ||
			clientUpgrades >= manager.httpConfiguration.MaxUpgradeConnectionsPerClient)) ||
		!binding.runtime.Acquire(upgrade, http2, manager.httpConfiguration) {
		manager.mutex.Unlock()
		http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	manager.httpActiveRequests++
	if upgrade {
		manager.httpActiveUpgrades++
	}
	manager.mutex.Unlock()

	defer func() {
		binding.runtime.Release(upgrade, http2)
		manager.mutex.Lock()
		manager.httpActiveRequests--
		if upgrade {
			manager.httpActiveUpgrades--
		}
		manager.mutex.Unlock()
	}()
	binding.runtime.ServeHTTP(writer, request)
}
