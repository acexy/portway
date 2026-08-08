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
	httpsEnabled bool,
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
			if declaration.RemotePort == 0 || declaration.Domain != "" ||
				len(declaration.PublicSchemes) != 0 {
				result := rejectedSyncResult(revision, protocol.ProxyErrorInvalidProxy, declaration.Name, "invalid TCP proxy declaration")
				return &result
			}
			if _, duplicate := tcpPorts[declaration.RemotePort]; duplicate {
				result := rejectedSyncResult(revision, protocol.ProxyErrorInvalidProxy, declaration.Name, "duplicate TCP remote port")
				return &result
			}
			tcpPorts[declaration.RemotePort] = struct{}{}
		case protocol.ProxyTypeUDP:
			if declaration.RemotePort == 0 || declaration.Domain != "" ||
				len(declaration.PublicSchemes) != 0 {
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
				config.ValidateHTTPDomain(declaration.Domain) != nil ||
				!validPublicSchemes(declaration.PublicSchemes) {
				result := rejectedSyncResult(revision, protocol.ProxyErrorInvalidProxy, declaration.Name, "invalid HTTP proxy declaration")
				return &result
			}
			if (declaration.AllowsPublicScheme(protocol.HTTPPublicSchemeHTTP) &&
				!httpEnabled) ||
				(declaration.AllowsPublicScheme(protocol.HTTPPublicSchemeHTTPS) &&
					!httpsEnabled) {
				result := rejectedSyncResult(
					revision,
					protocol.ProxyErrorPublicSchemeUnavailable,
					declaration.Name,
					"requested public scheme is unavailable",
				)
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

func validPublicSchemes(schemes []protocol.HTTPPublicScheme) bool {
	if len(schemes) == 0 {
		return true
	}
	seen := make(map[protocol.HTTPPublicScheme]struct{}, len(schemes))
	for _, scheme := range schemes {
		if scheme != protocol.HTTPPublicSchemeHTTP &&
			scheme != protocol.HTTPPublicSchemeHTTPS {
			return false
		}
		if _, duplicate := seen[scheme]; duplicate {
			return false
		}
		seen[scheme] = struct{}{}
	}
	return true
}
