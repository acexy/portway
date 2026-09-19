package config

import (
	"errors"
	"fmt"
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
	if err := validateVirtualNetworkConfig(configuration.VirtualNetwork); err != nil {
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
	bindIP, err := netip.ParseAddr(configuration.Proxies.BindIP)
	if err != nil || bindIP.String() != configuration.Proxies.BindIP {
		return errors.New("proxies.bind_ip must be a canonical IP address")
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
		} else if localIP, err := netip.ParseAddr(proxy.Local.IP); err != nil || localIP.String() != proxy.Local.IP {
			return fmt.Errorf("%s[%d].local.ip must be a canonical IP address", field, index)
		}
		if proxy.Local.Port == 0 {
			return fmt.Errorf("%s[%d].local.port must be between 1 and 65535", field, index)
		}
	}
	return nil
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
