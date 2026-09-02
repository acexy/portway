package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

func validateClient(configuration ClientConfig) error {
	if err := validateLogLevel(configuration.LogLevel); err != nil {
		return err
	}
	if configuration.Authentication.ClientID != "" {
		if err := ValidateClientID(configuration.Authentication.ClientID); err != nil {
			return err
		}
	}
	if err := validateClientTransport(configuration.Transport); err != nil {
		return err
	}
	if err := validateClientAuthentication(configuration.Authentication); err != nil {
		return err
	}
	if err := validateProxies(configuration.Proxies, "proxies"); err != nil {
		return err
	}
	if err := validateForwards(configuration.Forwards, "forwards"); err != nil {
		return err
	}
	return validateProxyForwardNames(configuration.Proxies, configuration.Forwards)
}

// ValidateClientID validates a configured or protocol-provided client ID.
func ValidateClientID(clientID string) error {
	if !clientIDPattern.MatchString(clientID) {
		return errors.New("client_id must contain 1 to 64 letters, digits, dots, underscores, or hyphens")
	}
	return nil
}

// ValidateProxyName applies the single proxy-name rule shared by configuration
// loading and runtime registration.
func ValidateProxyName(name string) error {
	if !proxyNamePattern.MatchString(name) {
		return errors.New("proxy name has an invalid format")
	}
	return nil
}

func validateServer(configuration ServerConfig) error {
	if err := validateLogLevel(configuration.LogLevel); err != nil {
		return err
	}
	if err := validateServerTransport(configuration.Transport); err != nil {
		return err
	}
	listenerAddresses := []struct {
		field   string
		address string
	}{
		{"transport.listen_address", configuration.Transport.ListenAddress},
		{"proxies.http.listen_address", configuration.Proxies.HTTP.ListenAddress},
		{"proxies.https.listen_address", configuration.Proxies.HTTPS.ListenAddress},
		{"operations.listen_address", configuration.Operations.ListenAddress},
	}
	for index, listener := range listenerAddresses {
		if listener.address == "" {
			continue
		}
		for _, previous := range listenerAddresses[:index] {
			if previous.address != "" && listener.address == previous.address {
				return fmt.Errorf("%s must differ from %s", listener.field, previous.field)
			}
		}
	}
	if err := ValidateHTTPSConfig(configuration.Proxies.HTTPS); err != nil {
		return err
	}
	if configuration.Proxies.HTTPS.ListenAddress != "" &&
		len(configuration.Proxies.HTTPS.Certificates) == 0 {
		return errors.New(
			"proxies.https.certificates is required when proxies.https.listen_address is configured",
		)
	}
	if err := validateHTTPConfig(configuration.Proxies.HTTP.HTTPConfig); err != nil {
		return err
	}
	if err := validateUDPConfig(configuration.Proxies.UDP); err != nil {
		return err
	}
	if err := validateForwardServerConfig(configuration.Forwards); err != nil {
		return err
	}
	if strings.TrimSpace(configuration.Security.HTTPClientIPHeader) !=
		configuration.Security.HTTPClientIPHeader {
		return errors.New(
			"security.http_client_ip_header must not contain surrounding whitespace",
		)
	}
	if configuration.Security.HTTPClientIPHeader != "" {
		if configuration.Security.IPDenyFile == "" {
			return errors.New(
				"security.http_client_ip_header requires security.ip_deny_file",
			)
		}
		if !httpHeaderNamePattern.MatchString(
			configuration.Security.HTTPClientIPHeader,
		) {
			return errors.New(
				"security.http_client_ip_header must be a valid HTTP header name",
			)
		}
		if configuration.Proxies.HTTP.ListenAddress == "" &&
			configuration.Proxies.HTTPS.ListenAddress == "" {
			return errors.New(
				"security.http_client_ip_header requires an HTTP or HTTPS listener",
			)
		}
	}
	if configuration.Proxies.BindIP == "" {
		return errors.New("proxies.bind_ip is required")
	}
	if net.ParseIP(configuration.Proxies.BindIP) == nil {
		return errors.New("proxies.bind_ip must be an IP address")
	}
	return validateServerAuthentication(configuration.Authentication)
}

func validateClientTransport(configuration ClientTransportConfig) error {
	switch configuration.Type {
	case transport.TypeTCP:
		if configuration.ServerAddress == "" {
			return errors.New("transport.server_address is required")
		}
		return nil
	case transport.TypeQUIC:
		if configuration.ServerAddress == "" {
			return errors.New("transport.server_address is required")
		}
		if configuration.QUIC.ServerName == "" {
			return errors.New("transport.quic.server_name is required")
		}
		return nil
	default:
		return fmt.Errorf("transport.type must be tcp or quic, got %q", configuration.Type)
	}
}

func validateServerTransport(configuration ServerTransportConfig) error {
	switch configuration.Type {
	case transport.TypeTCP:
		if configuration.ListenAddress == "" {
			return errors.New("transport.listen_address is required")
		}
		return nil
	case transport.TypeQUIC:
		if configuration.ListenAddress == "" {
			return errors.New("transport.listen_address is required")
		}
		if configuration.QUIC.CertFile == "" {
			return errors.New("transport.quic.cert_file is required")
		}
		if configuration.QUIC.KeyFile == "" {
			return errors.New("transport.quic.key_file is required")
		}
		return nil
	default:
		return fmt.Errorf("transport.type must be tcp or quic, got %q", configuration.Type)
	}
}

func validateLogLevel(logLevel LogLevel) error {
	switch logLevel {
	case LogLevelTrace, LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError:
		return nil
	default:
		return fmt.Errorf(
			"log_level must be trace, debug, info, warn, or error, got %q",
			logLevel,
		)
	}
}

func validateClientAuthentication(authentication ClientAuthenticationConfig) error {
	if authentication.Token == "" {
		return errors.New("authentication.token is required")
	}
	if err := validateToken(authentication.Token); err != nil {
		return fmt.Errorf("authentication.token: %w", err)
	}
	return nil
}

func validateServerAuthentication(authentication ServerAuthenticationConfig) error {
	if authentication.SharedToken != nil &&
		*authentication.SharedToken != "" {
		if err := validateToken(*authentication.SharedToken); err != nil {
			return fmt.Errorf("authentication.shared_token: %w", err)
		}
	}
	return nil
}

func validateToken(token string) error {
	if !utf8.ValidString(token) {
		return errors.New("must be valid UTF-8")
	}
	if utf8.RuneCountInString(token) <= generatedTokenBytes {
		return fmt.Errorf("must contain more than %d UTF-8 characters", generatedTokenBytes)
	}
	return nil
}

func validateManagedProxies(proxies []ProxyConfig) error {
	return validateProxies(proxies, "configuration.proxies")
}

func validateManagedConfiguration(configuration ManagedConfiguration) error {
	if err := validateManagedProxies(configuration.Proxies); err != nil {
		return err
	}
	if err := validateForwards(configuration.Forwards, "configuration.forwards"); err != nil {
		return err
	}
	return validateProxyForwardNames(configuration.Proxies, configuration.Forwards)
}

func validateConfiguredPublicSchemeAvailability(configuration ServerConfig) error {
	for clientID, client := range configuration.GovernedClients {
		if client.Permissions.Proxies.HTTP == nil {
			continue
		}
		for _, scheme := range client.Permissions.Proxies.HTTP.PublicSchemes {
			if err := validatePublicSchemeListener(
				configuration,
				scheme,
				fmt.Sprintf("governed client %q", clientID),
			); err != nil {
				return err
			}
		}
	}
	for clientID, client := range configuration.ManagedClients {
		for _, proxy := range client.Configuration.Proxies {
			if proxy.Type != protocol.ProxyTypeHTTP {
				continue
			}
			for _, scheme := range proxy.Public.Schemes {
				if err := validatePublicSchemeListener(
					configuration,
					scheme,
					fmt.Sprintf("managed client %q proxy %q", clientID, proxy.Name),
				); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validatePublicSchemeListener(
	configuration ServerConfig,
	scheme protocol.HTTPPublicScheme,
	owner string,
) error {
	switch scheme {
	case protocol.HTTPPublicSchemeHTTP:
		if configuration.Proxies.HTTP.ListenAddress == "" {
			return fmt.Errorf("%s requires the public HTTP listener", owner)
		}
	case protocol.HTTPPublicSchemeHTTPS:
		if configuration.Proxies.HTTPS.ListenAddress == "" {
			return fmt.Errorf("%s requires the public HTTPS listener", owner)
		}
	}
	return nil
}

func validateProxies(proxies []ProxyConfig, field string) error {
	if len(proxies) > hardMaxProxiesPerClient {
		return fmt.Errorf(
			"%s must contain at most %d entries",
			field,
			hardMaxProxiesPerClient,
		)
	}
	names := make(map[string]struct{}, len(proxies))
	tcpPorts := make(map[uint16]struct{})
	udpPorts := make(map[uint16]struct{})
	httpDomains := make(map[string]struct{})
	for index, proxy := range proxies {
		if err := ValidateProxyName(proxy.Name); err != nil {
			return fmt.Errorf("%s[%d].name has an invalid format", field, index)
		}
		if _, duplicate := names[proxy.Name]; duplicate {
			return fmt.Errorf("%s[%d].name is duplicated", field, index)
		}
		names[proxy.Name] = struct{}{}
		switch proxy.Type {
		case protocol.ProxyTypeTCP:
			if proxy.Public.Port == 0 || proxy.Public.Domain != "" ||
				len(proxy.Public.Schemes) != 0 {
				return fmt.Errorf("%s[%d] has invalid %s fields", field, index, proxy.Type)
			}
			if _, duplicate := tcpPorts[proxy.Public.Port]; duplicate {
				return fmt.Errorf(
					"%s[%d].public.port is duplicated for tcp",
					field,
					index,
				)
			}
			tcpPorts[proxy.Public.Port] = struct{}{}
		case protocol.ProxyTypeUDP:
			if proxy.Public.Port == 0 || proxy.Public.Domain != "" ||
				len(proxy.Public.Schemes) != 0 {
				return fmt.Errorf("%s[%d] has invalid %s fields", field, index, proxy.Type)
			}
			if _, duplicate := udpPorts[proxy.Public.Port]; duplicate {
				return fmt.Errorf(
					"%s[%d].public.port is duplicated for udp",
					field,
					index,
				)
			}
			udpPorts[proxy.Public.Port] = struct{}{}
		case protocol.ProxyTypeHTTP:
			if proxy.Public.Port != 0 {
				return fmt.Errorf("%s[%d].public.port is not allowed for http", field, index)
			}
			if err := ValidateHTTPDomain(proxy.Public.Domain); err != nil {
				return fmt.Errorf("%s[%d].public.domain: %w", field, index, err)
			}
			if len(proxy.Public.Schemes) == 0 {
				proxy.Public.Schemes = []protocol.HTTPPublicScheme{
					protocol.HTTPPublicSchemeHTTP,
				}
				proxies[index].Public.Schemes = proxy.Public.Schemes
			}
			if err := validateHTTPPublicSchemes(
				proxy.Public.Schemes,
				fmt.Sprintf("%s[%d].public.schemes", field, index),
			); err != nil {
				return err
			}
			if _, duplicate := httpDomains[proxy.Public.Domain]; duplicate {
				return fmt.Errorf(
					"%s[%d].public.domain is duplicated",
					field,
					index,
				)
			}
			httpDomains[proxy.Public.Domain] = struct{}{}
		default:
			return fmt.Errorf("%s[%d].type must be tcp, udp, or http", field, index)
		}
		if proxy.Local.IP == "" {
			proxies[index].Local.IP = "127.0.0.1"
		} else if net.ParseIP(proxy.Local.IP) == nil {
			return fmt.Errorf("%s[%d].local.ip must be an IP address", field, index)
		}
		if proxy.Local.Port == 0 {
			return fmt.Errorf("%s[%d].local.port must be between 1 and 65535", field, index)
		}
	}
	return nil
}

func validateForwards(forwards []ForwardConfig, field string) error {
	if len(forwards) > hardMaxProxiesPerClient {
		return fmt.Errorf("%s must contain at most %d entries", field, hardMaxProxiesPerClient)
	}
	names := make(map[string]struct{}, len(forwards))
	listeners := make(map[string]struct{}, len(forwards))
	for index, forward := range forwards {
		if err := ValidateProxyName(forward.Name); err != nil {
			return fmt.Errorf("%s[%d].name has an invalid format", field, index)
		}
		if _, duplicate := names[forward.Name]; duplicate {
			return fmt.Errorf("%s[%d].name is duplicated", field, index)
		}
		names[forward.Name] = struct{}{}
		switch forward.Type {
		case protocol.ForwardTypeTCP, protocol.ForwardTypeUDP:
		default:
			return fmt.Errorf("%s[%d].type must be tcp or udp", field, index)
		}
		listenAddress, err := netip.ParseAddr(forward.Listen.IP)
		if err != nil || listenAddress.String() != forward.Listen.IP {
			return fmt.Errorf("%s[%d].listen.ip must be a canonical IP address", field, index)
		}
		if forward.Listen.Port == 0 {
			return fmt.Errorf("%s[%d].listen.port must be between 1 and 65535", field, index)
		}
		targetAddress, err := netip.ParseAddr(forward.Target.IP)
		if err != nil || targetAddress.String() != forward.Target.IP {
			return fmt.Errorf("%s[%d].target.ip must be a canonical IP address", field, index)
		}
		if forward.Target.Port == 0 {
			return fmt.Errorf("%s[%d].target.port must be between 1 and 65535", field, index)
		}
		listener := fmt.Sprintf("%s/%s/%d", forward.Type, listenAddress, forward.Listen.Port)
		if _, duplicate := listeners[listener]; duplicate {
			return fmt.Errorf("%s[%d] duplicates a %s listener", field, index, forward.Type)
		}
		listeners[listener] = struct{}{}
	}
	return nil
}

func validateProxyForwardNames(proxies []ProxyConfig, forwards []ForwardConfig) error {
	names := make(map[string]struct{}, len(proxies))
	for _, proxy := range proxies {
		names[proxy.Name] = struct{}{}
	}
	for index, forward := range forwards {
		if _, duplicate := names[forward.Name]; duplicate {
			return fmt.Errorf("forwards[%d].name duplicates a proxy name", index)
		}
	}
	return nil
}

func validateForwardServerConfig(configuration ForwardServerConfig) error {
	if configuration.Configured && len(configuration.Rules) == 0 {
		return errors.New("forwards.rules must not be empty when forwards is configured")
	}
	if configuration.Enabled && len(configuration.Rules) == 0 {
		return errors.New("forwards.rules must not be empty when forwards.enabled is true")
	}
	if err := validateForwardRules("forwards.rules", configuration.Rules); err != nil {
		return err
	}
	return validateUDPConfig(EffectiveForwardUDPConfig(configuration))
}

func validateForwardRules(field string, rules []ForwardIPRule) error {
	prefixes := make([]netip.Prefix, len(rules))
	for index, rule := range rules {
		prefix, err := netip.ParsePrefix(rule.IPRange)
		if err != nil || prefix.String() != rule.IPRange || prefix != prefix.Masked() {
			return fmt.Errorf("%s[%d].ip_range must be a canonical CIDR", field, index)
		}
		if len(rule.TCP.PortRanges) == 0 && len(rule.UDP.PortRanges) == 0 {
			return fmt.Errorf("%s[%d] must contain tcp or udp port ranges", field, index)
		}
		if err := validateSortedPortRanges(
			fmt.Sprintf("%s[%d].tcp.port_ranges", field, index),
			rule.TCP.PortRanges,
		); err != nil {
			return err
		}
		if err := validateSortedPortRanges(
			fmt.Sprintf("%s[%d].udp.port_ranges", field, index),
			rule.UDP.PortRanges,
		); err != nil {
			return err
		}
		for previousIndex, previous := range prefixes[:index] {
			if previous.Contains(prefix.Addr()) || prefix.Contains(previous.Addr()) {
				return fmt.Errorf(
					"%s[%d].ip_range overlaps %s[%d].ip_range",
					field,
					index,
					field,
					previousIndex,
				)
			}
		}
		prefixes[index] = prefix
	}
	return nil
}

func validateSortedPortRanges(field string, ranges []PortRange) error {
	var previousEnd uint16
	for index, portRange := range ranges {
		if portRange.Start == 0 || portRange.End == 0 || portRange.Start > portRange.End {
			return fmt.Errorf("%s[%d] is invalid", field, index)
		}
		if index > 0 && portRange.Start <= previousEnd {
			return fmt.Errorf("%s must be sorted and non-overlapping", field)
		}
		previousEnd = portRange.End
	}
	return nil
}

// ForwardTargetAllowed reports whether one concrete target matches one rule.
func ForwardTargetAllowed(
	rules []ForwardIPRule,
	forwardType protocol.ForwardType,
	targetIP string,
	targetPort uint16,
) bool {
	_, allowed := MatchingForwardRule(rules, forwardType, targetIP, targetPort)
	return allowed
}

// MatchingForwardRule returns the unique rule authorizing one target.
func MatchingForwardRule(
	rules []ForwardIPRule,
	forwardType protocol.ForwardType,
	targetIP string,
	targetPort uint16,
) (ForwardIPRule, bool) {
	address, err := netip.ParseAddr(targetIP)
	if err != nil || targetPort == 0 {
		return ForwardIPRule{}, false
	}
	for _, rule := range rules {
		prefix, parseError := netip.ParsePrefix(rule.IPRange)
		if parseError != nil || !prefix.Contains(address) {
			continue
		}
		var ranges []PortRange
		switch forwardType {
		case protocol.ForwardTypeTCP:
			ranges = rule.TCP.PortRanges
		case protocol.ForwardTypeUDP:
			ranges = rule.UDP.PortRanges
		default:
			return ForwardIPRule{}, false
		}
		for _, portRange := range ranges {
			if targetPort >= portRange.Start && targetPort <= portRange.End {
				return rule, true
			}
		}
		return ForwardIPRule{}, false
	}
	return ForwardIPRule{}, false
}

// ValidateForwardConfiguration validates cross-file Forward safety boundaries.
func ValidateForwardConfiguration(configuration ServerConfig) error {
	if err := validateForwardServerConfig(configuration.Forwards); err != nil {
		return err
	}
	return validateForwardConfiguration(configuration)
}

func validateHTTPPublicSchemes(
	schemes []protocol.HTTPPublicScheme,
	field string,
) error {
	if len(schemes) == 0 {
		return fmt.Errorf("%s must not be empty for http", field)
	}
	seen := make(map[protocol.HTTPPublicScheme]struct{}, len(schemes))
	for index, scheme := range schemes {
		switch scheme {
		case protocol.HTTPPublicSchemeHTTP, protocol.HTTPPublicSchemeHTTPS:
		default:
			return fmt.Errorf("%s[%d] must be http or https", field, index)
		}
		if _, duplicate := seen[scheme]; duplicate {
			return fmt.Errorf("%s contains duplicate scheme %q", field, scheme)
		}
		seen[scheme] = struct{}{}
	}
	return nil
}

// ValidateManagedProxies validates a complete server-owned client proxy set.
func ValidateManagedProxies(proxies []ProxyConfig) error {
	return validateManagedProxies(proxies)
}

// ValidateManagedForwards validates one server-owned client Forward set.
func ValidateManagedForwards(forwards []ForwardConfig) error {
	return validateForwards(forwards, "configuration.forwards")
}
