package config

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

func validateClient(configuration ClientConfig) error {
	if err := validateLogLevel(configuration.LogLevel); err != nil {
		return err
	}
	if configuration.ClientID != "" {
		if err := ValidateClientID(configuration.ClientID); err != nil {
			return err
		}
	}
	if err := validateClientTransport(configuration.Transport); err != nil {
		return err
	}
	if err := validateClientAuthentication(configuration.Authentication); err != nil {
		return err
	}
	return validateProxies(configuration.Proxies, "proxies")
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
		{"tunnel.http_listen_address", configuration.Tunnel.HTTPListenAddress},
		{"tunnel.https_listen_address", configuration.Tunnel.HTTPSListenAddress},
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
	if err := ValidateHTTPSConfig(configuration.HTTPS); err != nil {
		return err
	}
	if configuration.Tunnel.HTTPSListenAddress != "" &&
		len(configuration.HTTPS.Certificates) == 0 {
		return errors.New(
			"https.certificates is required when tunnel.https_listen_address is configured",
		)
	}
	if err := validateHTTPConfig(configuration.HTTP); err != nil {
		return err
	}
	if err := validateUDPConfig(configuration.UDP); err != nil {
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
		if configuration.Tunnel.HTTPListenAddress == "" &&
			configuration.Tunnel.HTTPSListenAddress == "" {
			return errors.New(
				"security.http_client_ip_header requires an HTTP or HTTPS listener",
			)
		}
	}
	if configuration.Tunnel.BindIP == "" {
		return errors.New("tunnel.bind_ip is required")
	}
	if net.ParseIP(configuration.Tunnel.BindIP) == nil {
		return errors.New("tunnel.bind_ip must be an IP address")
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
	if len(authentication.Token) < generatedTokenBytes {
		return fmt.Errorf("authentication.token must contain at least %d bytes", generatedTokenBytes)
	}
	return nil
}

func validateServerAuthentication(authentication ServerAuthenticationConfig) error {
	if authentication.SharedToken != nil &&
		*authentication.SharedToken != "" &&
		len(*authentication.SharedToken) < generatedTokenBytes {
		return fmt.Errorf(
			"authentication.shared_token must contain at least %d bytes",
			generatedTokenBytes,
		)
	}
	return nil
}

func validateManagedProxies(proxies []ProxyConfig) error {
	return validateProxies(proxies, "configuration.proxies")
}

func validateConfiguredPublicSchemeAvailability(configuration ServerConfig) error {
	for clientID, client := range configuration.GovernedClients {
		for _, scheme := range client.Permissions.HTTP.PublicSchemes {
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
			for _, scheme := range proxy.PublicSchemes {
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
		if configuration.Tunnel.HTTPListenAddress == "" {
			return fmt.Errorf("%s requires the public HTTP listener", owner)
		}
	case protocol.HTTPPublicSchemeHTTPS:
		if configuration.Tunnel.HTTPSListenAddress == "" {
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
			if proxy.RemotePort == 0 || proxy.Domain != "" ||
				len(proxy.PublicSchemes) != 0 {
				return fmt.Errorf("%s[%d] has invalid %s fields", field, index, proxy.Type)
			}
			if _, duplicate := tcpPorts[proxy.RemotePort]; duplicate {
				return fmt.Errorf(
					"%s[%d].remote_port is duplicated for tcp",
					field,
					index,
				)
			}
			tcpPorts[proxy.RemotePort] = struct{}{}
		case protocol.ProxyTypeUDP:
			if proxy.RemotePort == 0 || proxy.Domain != "" ||
				len(proxy.PublicSchemes) != 0 {
				return fmt.Errorf("%s[%d] has invalid %s fields", field, index, proxy.Type)
			}
			if _, duplicate := udpPorts[proxy.RemotePort]; duplicate {
				return fmt.Errorf(
					"%s[%d].remote_port is duplicated for udp",
					field,
					index,
				)
			}
			udpPorts[proxy.RemotePort] = struct{}{}
		case protocol.ProxyTypeHTTP:
			if proxy.RemotePort != 0 {
				return fmt.Errorf("%s[%d].remote_port is not allowed for http", field, index)
			}
			if err := ValidateHTTPDomain(proxy.Domain); err != nil {
				return fmt.Errorf("%s[%d].domain: %w", field, index, err)
			}
			if len(proxy.PublicSchemes) == 0 {
				proxy.PublicSchemes = []protocol.HTTPPublicScheme{
					protocol.HTTPPublicSchemeHTTP,
				}
				proxies[index].PublicSchemes = proxy.PublicSchemes
			}
			if err := validateHTTPPublicSchemes(
				proxy.PublicSchemes,
				fmt.Sprintf("%s[%d].public_schemes", field, index),
			); err != nil {
				return err
			}
			if _, duplicate := httpDomains[proxy.Domain]; duplicate {
				return fmt.Errorf(
					"%s[%d].domain is duplicated",
					field,
					index,
				)
			}
			httpDomains[proxy.Domain] = struct{}{}
		default:
			return fmt.Errorf("%s[%d].type must be tcp, udp, or http", field, index)
		}
		if proxy.LocalIP == "" {
			proxies[index].LocalIP = "127.0.0.1"
		} else if net.ParseIP(proxy.LocalIP) == nil {
			return fmt.Errorf("%s[%d].local_ip must be an IP address", field, index)
		}
		if proxy.LocalPort == 0 {
			return fmt.Errorf("%s[%d].local_port must be between 1 and 65535", field, index)
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
