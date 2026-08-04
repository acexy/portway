package registry

import (
	"context"
	"net"
	"time"

	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
)

func (manager *Registry) openVisitor(
	endpoint *proxytcp.Endpoint,
	binding *tcpProxyBinding,
	visitor net.Conn,
) {
	startedAt := time.Now()
	remoteAddress := visitor.RemoteAddr().String()
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
		manager.logger.WithComponent("proxy_tcp").DebugWithFields(
			"TCP visitor rejected",
			map[string]any{
				"event":          "tcp_visitor_rejected",
				"client_id":      binding.clientID,
				"proxy_name":     binding.declaration.Name,
				"proxy_type":     protocol.ProxyTypeTCP,
				"remote_address": remoteAddress,
				"reason":         "proxy_inactive",
			},
		)
		visitor.Close()
		return
	}
	writer := state.writer
	sessionID := state.sessionID
	authenticationContext := state.authentication
	maxActiveLinks := state.maxActiveLinks
	manager.mutex.Unlock()
	visitorLogger := manager.logger.WithComponent("proxy_tcp").WithFields(map[string]any{
		"client_id":      binding.clientID,
		"session_id":     sessionID,
		"proxy_name":     binding.declaration.Name,
		"proxy_type":     protocol.ProxyTypeTCP,
		"remote_address": remoteAddress,
	})
	visitorLogger.DebugWithFields("TCP visitor accepted", map[string]any{
		"event":  "tcp_visitor_accepted",
		"result": "accepted",
	})

	err := manager.linkBroker.ServeStream(
		link.Target{
			ClientID: binding.clientID, SessionID: sessionID,
			ProxyName: binding.declaration.Name, ProxyType: protocol.ProxyTypeTCP,
			BindingID: binding.bindingID, Writer: writer,
			Authentication: authenticationContext,
			MaxActiveLinks: maxActiveLinks,
		},
		func() { visitor.Close() },
		func(ctx context.Context, stream net.Conn) error {
			return proxytcp.Forward(ctx, visitor, stream)
		},
	)
	if err != nil {
		visitor.Close()
	}
	result := "completed"
	if err != nil {
		result = "failed"
	}
	visitorLogger.DebugWithFields("TCP visitor closed", map[string]any{
		"event":       "tcp_visitor_closed",
		"result":      result,
		"duration_ms": time.Since(startedAt).Milliseconds(),
	})
}
