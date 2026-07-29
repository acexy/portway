package registry

import (
	"context"
	"net"

	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
)

func (manager *Registry) openVisitor(
	endpoint *proxytcp.Endpoint,
	binding *tcpProxyBinding,
	visitor net.Conn,
) {
	manager.mutex.Lock()
	state, exists := manager.clients[binding.clientID]
	if manager.closed ||
		!exists ||
		!state.active ||
		state.sessionID != binding.sessionID ||
		manager.endpointBindings[binding.declaration.RemotePort] != binding ||
		state.tcpProxies[binding.declaration.Name] != binding ||
		state.writer == nil {
		manager.mutex.Unlock()
		visitor.Close()
		return
	}
	writer := state.writer
	sessionID := state.sessionID
	manager.mutex.Unlock()

	err := manager.linkBroker.ServeStream(
		link.Target{
			ClientID: binding.clientID, SessionID: sessionID,
			ProxyName: binding.declaration.Name, ProxyType: protocol.ProxyTypeTCP,
			BindingID: binding.bindingID, Writer: writer,
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
