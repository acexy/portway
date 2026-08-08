package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
)

func negotiateCapabilities(clientCapabilities []string) []string {
	supported := map[string]struct{}{
		"tcp":          {},
		"udp":          {},
		"http":         {},
		"json-control": {},
	}
	negotiated := coll.SliceFilter(
		clientCapabilities,
		func(capability string) bool {
			_, supportedCapability := supported[capability]
			return supportedCapability
		},
	)
	if negotiated == nil {
		return []string{}
	}
	return negotiated
}

func (s *Service) validateGovernedProxies(
	clientID string,
	request protocol.SyncProxies,
) *protocol.SyncResult {
	clientConfiguration, exists := s.configuration.governedClient(clientID)
	if !exists {
		return governedRejection(
			request.Revision,
			protocol.ProxyErrorInvalidRequest,
			"",
			"governed client configuration is unavailable",
		)
	}
	permissions := clientConfiguration.Permissions
	allowedTypes := make(map[string]struct{}, len(permissions.ProxyTypes))
	for _, proxyType := range permissions.ProxyTypes {
		allowedTypes[proxyType] = struct{}{}
	}
	typeCounts := make(map[protocol.ProxyType]int)
	for _, declaration := range request.Proxies {
		if _, allowed := allowedTypes[string(declaration.Type)]; !allowed {
			return governedRejection(
				request.Revision,
				protocol.ProxyErrorProxyTypeNotAllowed,
				declaration.Name,
				"proxy type is not allowed",
			)
		}
		typeCounts[declaration.Type]++
		switch declaration.Type {
		case protocol.ProxyTypeTCP:
			if !portAllowed(declaration.RemotePort, permissions.TCP.RemotePortRanges) {
				return governedRejection(
					request.Revision,
					protocol.ProxyErrorRemotePortNotAllowed,
					declaration.Name,
					"remote TCP port is not allowed",
				)
			}
		case protocol.ProxyTypeUDP:
			if !portAllowed(declaration.RemotePort, permissions.UDP.RemotePortRanges) {
				return governedRejection(
					request.Revision,
					protocol.ProxyErrorRemotePortNotAllowed,
					declaration.Name,
					"remote UDP port is not allowed",
				)
			}
		case protocol.ProxyTypeHTTP:
			if !domainAllowed(declaration.Domain, permissions.HTTP.Domains) {
				return governedRejection(
					request.Revision,
					protocol.ProxyErrorDomainNotAllowed,
					declaration.Name,
					"HTTP domain is not allowed",
				)
			}
			for _, scheme := range declaration.PublicSchemes {
				if !publicSchemeAllowed(scheme, permissions.HTTP.PublicSchemes) {
					return governedRejection(
						request.Revision,
						protocol.ProxyErrorPublicSchemeNotAllowed,
						declaration.Name,
						"HTTP public scheme is not allowed",
					)
				}
			}
		}
	}
	limits := permissions.Limits
	if (limits.MaxProxies > 0 && len(request.Proxies) > limits.MaxProxies) ||
		(limits.MaxTCPProxies > 0 &&
			typeCounts[protocol.ProxyTypeTCP] > limits.MaxTCPProxies) ||
		(limits.MaxUDPProxies > 0 &&
			typeCounts[protocol.ProxyTypeUDP] > limits.MaxUDPProxies) ||
		(limits.MaxHTTPProxies > 0 &&
			typeCounts[protocol.ProxyTypeHTTP] > limits.MaxHTTPProxies) {
		return governedRejection(
			request.Revision,
			protocol.ProxyErrorClientLimitExceeded,
			"",
			"client proxy limit exceeded",
		)
	}
	return nil
}

func publicSchemeAllowed(
	requested protocol.HTTPPublicScheme,
	allowed []protocol.HTTPPublicScheme,
) bool {
	if len(allowed) == 0 {
		return requested == protocol.HTTPPublicSchemeHTTP
	}
	for _, scheme := range allowed {
		if scheme == requested {
			return true
		}
	}
	return false
}

func portAllowed(port uint16, ranges []config.PortRange) bool {
	for _, portRange := range ranges {
		if port >= portRange.Start && port <= portRange.End {
			return true
		}
	}
	return false
}

func domainAllowed(domain string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == domain {
			return true
		}
		if !strings.HasPrefix(pattern, "*.") {
			continue
		}
		suffix := strings.TrimPrefix(pattern, "*.")
		if !strings.HasSuffix(domain, "."+suffix) {
			continue
		}
		prefix := strings.TrimSuffix(domain, "."+suffix)
		if prefix != "" && !strings.Contains(prefix, ".") {
			return true
		}
	}
	return false
}

func governedRejection(
	revision uint64,
	code protocol.ProxyErrorCode,
	proxyName string,
	message string,
) *protocol.SyncResult {
	return &protocol.SyncResult{
		Revision: revision,
		Status:   protocol.ProxySyncStatusRejected,
		Proxies:  []protocol.ProxyResult{},
		Error: &protocol.ProxyError{
			Code:      code,
			Message:   message,
			ProxyName: proxyName,
			Retryable: false,
		},
	}
}

func newSessionID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
