package registry

import (
	"errors"

	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
)

func (manager *Registry) newUDPBinding(
	clientID string,
	sessionID string,
	declaration protocol.ProxyDeclaration,
	endpoint *proxyudp.Endpoint,
) (*udpProxyBinding, error) {
	bindingID, err := newBindingID()
	if err != nil {
		return nil, err
	}
	binding := &udpProxyBinding{
		manager: manager,
		clientID: clientID,
		sessionID: sessionID,
		bindingID: bindingID,
		declaration: declaration,
		endpoint: endpoint,
	}
	binding.runtime = proxyudp.NewBinding(
		manager.context,
		manager.udpConfiguration,
		endpoint,
		manager.linkBroker,
		manager.udpLimiter,
		manager.sourceFilter,
		binding.resolveTarget,
	)
	return binding, nil
}

func (binding *udpProxyBinding) resolveTarget() (link.Target, error) {
	binding.manager.mutex.Lock()
	defer binding.manager.mutex.Unlock()
	state := binding.manager.clients[binding.clientID]
	if state == nil || !state.active || state.sessionID != binding.sessionID ||
		state.udpProxies[binding.declaration.Name] != binding ||
		state.writer == nil {
		return link.Target{}, errors.New("UDP proxy binding is inactive")
	}
	return link.Target{
		ClientID: binding.clientID,
		SessionID: binding.sessionID,
		ProxyName: binding.declaration.Name,
		ProxyType: protocol.ProxyTypeUDP,
		BindingID: binding.bindingID,
		Writer: state.writer,
	}, nil
}

func (binding *udpProxyBinding) close() {
	binding.runtime.Close()
}

func closeUDPBindings(
	bindings map[string]*udpProxyBinding,
	exclusions map[string]*udpProxyBinding,
) {
	for name, binding := range bindings {
		if exclusions[name] != binding {
			binding.close()
		}
	}
}

func closeUDPEndpoints(endpoints map[uint16]*proxyudp.Endpoint) {
	for _, endpoint := range endpoints {
		endpoint.Close()
	}
}
