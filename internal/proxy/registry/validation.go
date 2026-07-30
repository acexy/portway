package registry

import (
	"regexp"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
)

var proxyNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func validateProxyDeclarations(
	revision uint64,
	declarations []protocol.ProxyDeclaration,
	httpEnabled bool,
) *protocol.SyncResult {
	names := make(map[string]struct{}, len(declarations))
	tcpPorts := make(map[uint16]struct{})
	udpPorts := make(map[uint16]struct{})
	httpDomains := make(map[string]struct{})
	for _, declaration := range declarations {
		if !proxyNamePattern.MatchString(declaration.Name) {
			result := rejectedSyncResult(
				revision,
				protocol.ProxyErrorInvalidProxy,
				declaration.Name,
				"invalid proxy declaration",
			)
			return &result
		}
		switch declaration.Type {
		case protocol.ProxyTypeTCP:
			if declaration.RemotePort == 0 || declaration.Domain != "" {
				result := rejectedSyncResult(revision, protocol.ProxyErrorInvalidProxy, declaration.Name, "invalid TCP proxy declaration")
				return &result
			}
			if _, duplicate := tcpPorts[declaration.RemotePort]; duplicate {
				result := rejectedSyncResult(revision, protocol.ProxyErrorInvalidProxy, declaration.Name, "duplicate TCP remote port")
				return &result
			}
			tcpPorts[declaration.RemotePort] = struct{}{}
		case protocol.ProxyTypeUDP:
			if declaration.RemotePort == 0 || declaration.Domain != "" {
				result := rejectedSyncResult(revision, protocol.ProxyErrorInvalidProxy, declaration.Name, "invalid UDP proxy declaration")
				return &result
			}
			if _, duplicate := udpPorts[declaration.RemotePort]; duplicate {
				result := rejectedSyncResult(revision, protocol.ProxyErrorInvalidProxy, declaration.Name, "duplicate UDP remote port")
				return &result
			}
			udpPorts[declaration.RemotePort] = struct{}{}
		case protocol.ProxyTypeHTTP:
			if declaration.RemotePort != 0 ||
				config.ValidateHTTPDomain(declaration.Domain) != nil {
				result := rejectedSyncResult(revision, protocol.ProxyErrorInvalidProxy, declaration.Name, "invalid HTTP proxy declaration")
				return &result
			}
			if !httpEnabled {
				result := rejectedSyncResult(revision, protocol.ProxyErrorHTTPDisabled, declaration.Name, "HTTP listener is disabled")
				return &result
			}
			if _, duplicate := httpDomains[declaration.Domain]; duplicate {
				result := rejectedSyncResult(revision, protocol.ProxyErrorInvalidProxy, declaration.Name, "duplicate HTTP domain")
				return &result
			}
			httpDomains[declaration.Domain] = struct{}{}
		default:
			result := rejectedSyncResult(revision, protocol.ProxyErrorInvalidProxy, declaration.Name, "unsupported proxy type")
			return &result
		}
		if _, duplicate := names[declaration.Name]; duplicate {
			result := rejectedSyncResult(
				revision,
				protocol.ProxyErrorInvalidProxy,
				declaration.Name,
				"duplicate proxy name",
			)
			return &result
		}
		names[declaration.Name] = struct{}{}
	}
	return nil
}
