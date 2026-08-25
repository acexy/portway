package registry

import (
	"context"
	"errors"
	"net"
	"sync"
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
	localAddress := visitor.LocalAddr().String()
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
				"local_address":  localAddress,
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
		"local_address":  localAddress,
	})
	visitorLogger.DebugWithFields("TCP visitor accepted", map[string]any{
		"event":  "tcp_visitor_accepted",
		"result": "accepted",
	})
	var finishOnce sync.Once
	finish := func(
		linkID string,
		result string,
		reason string,
		streamStarted bool,
		forwardResult proxytcp.ForwardResult,
		forwardError error,
	) {
		finishOnce.Do(func() {
			fields := map[string]any{
				"event":                   "tcp_visitor_closed",
				"result":                  result,
				"reason":                  reason,
				"stream_started":          streamStarted,
				"visitor_to_client_bytes": forwardResult.LeftToRightBytes,
				"client_to_visitor_bytes": forwardResult.RightToLeftBytes,
				"duration_ms":             time.Since(startedAt).Milliseconds(),
			}
			if linkID != "" {
				fields["link_id"] = linkID
			}
			if forwardError != nil {
				fields["error_code"] = reason
				fields["error"] = forwardError
			}
			visitorLogger.DebugWithFields("TCP visitor closed", fields)
		})
	}

	linkID, err := manager.linkBroker.ServeStream(
		link.Target{
			ClientID: binding.clientID, SessionID: sessionID,
			ProxyName: binding.declaration.Name, ProxyType: protocol.ProxyTypeTCP,
			BindingID: binding.bindingID, Writer: writer,
			Authentication: authenticationContext,
			MaxActiveLinks: maxActiveLinks,
		},
		func(cancelledLinkID string) {
			visitor.Close()
			finish(cancelledLinkID, "cancelled", "link_cancelled", false, proxytcp.ForwardResult{}, nil)
		},
		func(ctx context.Context, activeLinkID string, stream net.Conn) error {
			visitorLogger.DebugWithFields("TCP stream started", map[string]any{
				"event":   "tcp_stream_started",
				"link_id": activeLinkID,
			})
			forwardResult, forwardError := proxytcp.Forward(ctx, visitor, stream)
			result := "completed"
			reason := "stream_closed"
			if forwardError != nil {
				result = "failed"
				reason = proxytcp.CloseReason(ctx, forwardError)
			}
			finish(activeLinkID, result, reason, true, forwardResult, forwardError)
			return forwardError
		},
	)
	if err != nil {
		visitor.Close()
		finish(linkID, "failed", tcpLinkRequestFailureReason(err), false, proxytcp.ForwardResult{}, err)
	}
}

func tcpLinkRequestFailureReason(err error) string {
	if errors.Is(err, link.ErrCapacityReached) {
		return "capacity_exceeded"
	}
	return "link_request_failed"
}
