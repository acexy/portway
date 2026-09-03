package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
	proxyregistry "github.com/acexy/portway/internal/proxy/registry"
)

func (s *Service) negotiateCapabilities(clientCapabilities []protocol.Capability) []protocol.Capability {
	supported := map[protocol.Capability]struct{}{
		protocol.CapabilityTCP:         {},
		protocol.CapabilityUDP:         {},
		protocol.CapabilityHTTP:        {},
		protocol.CapabilityJSONControl: {},
	}
	forwardConfiguration := s.configuration.snapshot().Forwards
	for _, rule := range forwardConfiguration.Rules {
		if len(rule.TCP.PortRanges) != 0 {
			supported[protocol.CapabilityTCPForward] = struct{}{}
		}
		if len(rule.UDP.PortRanges) != 0 {
			supported[protocol.CapabilityUDPForward] = struct{}{}
		}
	}
	negotiated := coll.SliceFilter(
		clientCapabilities,
		func(capability protocol.Capability) bool {
			_, supportedCapability := supported[capability]
			return supportedCapability
		},
	)
	if negotiated == nil {
		return []protocol.Capability{}
	}
	return negotiated
}

func forwardPolicyChanged(
	current config.ServerConfig,
	candidate config.ServerConfig,
	authenticationContext authentication.Context,
	declaration protocol.ForwardDeclaration,
) bool {
	if declaration.Type == protocol.ForwardTypeUDP && !reflect.DeepEqual(
		config.EffectiveForwardUDPConfig(current.Forwards),
		config.EffectiveForwardUDPConfig(candidate.Forwards),
	) {
		return true
	}
	currentGlobal, currentAllowed := config.MatchingForwardRule(
		current.Forwards.Rules,
		declaration.Type,
		declaration.TargetIP,
		declaration.TargetPort,
	)
	candidateGlobal, candidateAllowed := config.MatchingForwardRule(
		candidate.Forwards.Rules,
		declaration.Type,
		declaration.TargetIP,
		declaration.TargetPort,
	)
	currentAllowed = current.Forwards.Enabled && currentAllowed
	candidateAllowed = candidate.Forwards.Enabled && candidateAllowed
	if currentAllowed != candidateAllowed ||
		!reflect.DeepEqual(currentGlobal, candidateGlobal) {
		return true
	}
	currentRules := clientForwardRules(current, authenticationContext)
	candidateRules := clientForwardRules(candidate, authenticationContext)
	currentClientRule, currentClientAllowed := config.MatchingForwardRule(
		currentRules,
		declaration.Type,
		declaration.TargetIP,
		declaration.TargetPort,
	)
	candidateClientRule, candidateClientAllowed := config.MatchingForwardRule(
		candidateRules,
		declaration.Type,
		declaration.TargetIP,
		declaration.TargetPort,
	)
	if authenticationContext.Mode == authentication.ModeShared {
		return false
	}
	if authenticationContext.Mode == authentication.ModeManaged &&
		len(currentRules) == 0 && len(candidateRules) == 0 {
		return false
	}
	return currentClientAllowed != candidateClientAllowed ||
		!reflect.DeepEqual(currentClientRule, candidateClientRule)
}

func clientForwardRules(
	configuration config.ServerConfig,
	authenticationContext authentication.Context,
) []config.ForwardIPRule {
	switch authenticationContext.Mode {
	case authentication.ModeGoverned:
		return configuration.GovernedClients[authenticationContext.ClientID].Permissions.Forwards.Rules
	case authentication.ModeManaged:
		return configuration.ManagedClients[authenticationContext.ClientID].Permissions.Forwards.Rules
	default:
		return nil
	}
}

func (s *Service) forwardPolicy(
	authenticationContext authentication.Context,
	declaration protocol.ForwardDeclaration,
) (bool, bool) {
	configuration := s.configuration.snapshot()
	configured := config.ForwardTargetAllowed(
		configuration.Forwards.Rules,
		declaration.Type,
		declaration.TargetIP,
		declaration.TargetPort,
	)
	if !configured {
		return false, false
	}
	switch authenticationContext.Mode {
	case authentication.ModeShared:
		return true, configuration.Forwards.Enabled
	case authentication.ModeGoverned:
		client, exists := configuration.GovernedClients[authenticationContext.ClientID]
		if !exists {
			return false, false
		}
		configured = config.ForwardTargetAllowed(
			client.Permissions.Forwards.Rules,
			declaration.Type,
			declaration.TargetIP,
			declaration.TargetPort,
		)
	case authentication.ModeManaged:
		client, exists := configuration.ManagedClients[authenticationContext.ClientID]
		if !exists {
			return false, false
		}
		rules := client.Permissions.Forwards.Rules
		if len(rules) == 0 {
			return true, configuration.Forwards.Enabled
		}
		configured = config.ForwardTargetAllowed(
			rules,
			declaration.Type,
			declaration.TargetIP,
			declaration.TargetPort,
		)
	default:
		return false, false
	}
	return configured, configured && configuration.Forwards.Enabled
}

func (s *Service) validateGovernedProxies(
	clientID string,
	request proxyregistry.SyncRequest,
) *proxyregistry.SyncResult {
	clientConfiguration, exists := s.configuration.governedClient(clientID)
	if !exists {
		return governedRejection(
			request.Revision,
			proxyregistry.ErrorInvalidRequest,
			"",
			"governed client configuration is unavailable",
		)
	}
	permissions := clientConfiguration.Permissions.Proxies
	typeCounts := make(map[protocol.ProxyType]int)
	for _, declaration := range request.Proxies {
		allowed := (declaration.Type == protocol.ProxyTypeTCP && permissions.TCP != nil) ||
			(declaration.Type == protocol.ProxyTypeUDP && permissions.UDP != nil) ||
			(declaration.Type == protocol.ProxyTypeHTTP && permissions.HTTP != nil)
		if !allowed {
			return governedRejection(
				request.Revision,
				proxyregistry.ErrorProxyTypeNotAllowed,
				declaration.Name,
				"proxy type is not allowed",
			)
		}
		typeCounts[declaration.Type]++
		switch declaration.Type {
		case protocol.ProxyTypeTCP:
			if !portAllowed(declaration.RemotePort, permissions.TCP.PortRanges) {
				return governedRejection(
					request.Revision,
					proxyregistry.ErrorRemotePortNotAllowed,
					declaration.Name,
					"remote TCP port is not allowed",
				)
			}
		case protocol.ProxyTypeUDP:
			if !portAllowed(declaration.RemotePort, permissions.UDP.PortRanges) {
				return governedRejection(
					request.Revision,
					proxyregistry.ErrorRemotePortNotAllowed,
					declaration.Name,
					"remote UDP port is not allowed",
				)
			}
		case protocol.ProxyTypeHTTP:
			if !domainAllowed(declaration.Domain, permissions.HTTP.Domains) {
				return governedRejection(
					request.Revision,
					proxyregistry.ErrorDomainNotAllowed,
					declaration.Name,
					"HTTP domain is not allowed",
				)
			}
			for _, scheme := range declaration.PublicSchemes {
				if !publicSchemeAllowed(scheme, permissions.HTTP.PublicSchemes) {
					return governedRejection(
						request.Revision,
						proxyregistry.ErrorPublicSchemeNotAllowed,
						declaration.Name,
						"HTTP public scheme is not allowed",
					)
				}
			}
		}
	}
	limits := permissions.Limits
	if (limits.MaxTotal > 0 && len(request.Proxies) > limits.MaxTotal) ||
		(limits.MaxTCP > 0 && typeCounts[protocol.ProxyTypeTCP] > limits.MaxTCP) ||
		(limits.MaxUDP > 0 && typeCounts[protocol.ProxyTypeUDP] > limits.MaxUDP) ||
		(limits.MaxHTTP > 0 && typeCounts[protocol.ProxyTypeHTTP] > limits.MaxHTTP) {
		return governedRejection(
			request.Revision,
			proxyregistry.ErrorClientLimitExceeded,
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
	return coll.SliceContains(allowed, requested)
}

func portAllowed(port uint16, ranges []config.PortRange) bool {
	return coll.SliceContainsBy(ranges, func(portRange config.PortRange) bool {
		return port >= portRange.Start && port <= portRange.End
	})
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
	code proxyregistry.ErrorCode,
	proxyName string,
	message string,
) *proxyregistry.SyncResult {
	return &proxyregistry.SyncResult{
		Revision: revision,
		Status:   proxyregistry.SyncStatusRejected,
		Proxies:  []protocol.ProxyResult{},
		Error: &proxyregistry.Error{
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
