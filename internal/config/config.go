// Package config loads and validates Portway configuration files.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/acexy/portway/internal/transport"
	"gopkg.in/yaml.v3"
)

// LogLevel selects the minimum severity emitted by the process logger.
type LogLevel string

const (
	// LogLevelTrace enables detailed protocol and lifecycle diagnostics.
	LogLevelTrace LogLevel = "trace"
	// LogLevelDebug enables debug, informational, warning, and error logs.
	LogLevelDebug LogLevel = "debug"
	// LogLevelInfo enables informational, warning, and error logs.
	LogLevelInfo LogLevel = "info"
	// LogLevelWarn enables warning and error logs.
	LogLevelWarn LogLevel = "warn"
	// LogLevelError enables only error logs.
	LogLevelError LogLevel = "error"
)

const (
	generatedTokenBytes    = 32
	generatedClientIDBytes = 16
)

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var proxyNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var httpHeaderNamePattern = regexp.MustCompile(
	"^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$",
)

// AuthenticationConfig configures the shared Token identity proof.
type AuthenticationConfig struct {
	Token string `yaml:"token"`
}

// QUICClientTransportConfig configures the client side of the QUIC transport.
type QUICClientTransportConfig struct {
	ServerName string `yaml:"server_name"`
	CAFile     string `yaml:"ca_file"`
}

// ClientTransportConfig selects and configures one client transport.
type ClientTransportConfig struct {
	Type          transport.Type            `yaml:"type"`
	ServerAddress string                    `yaml:"server_address"`
	QUIC          QUICClientTransportConfig `yaml:"quic"`
}

// QUICServerTransportConfig configures the server side of the QUIC transport.
type QUICServerTransportConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// ServerTransportConfig selects and configures one server transport.
type ServerTransportConfig struct {
	Type          transport.Type            `yaml:"type"`
	ListenAddress string                    `yaml:"listen_address"`
	QUIC          QUICServerTransportConfig `yaml:"quic"`
}

// ProxyConfig describes one client-side proxy.
type ProxyConfig struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	LocalIP    string `yaml:"local_ip"`
	LocalPort  uint16 `yaml:"local_port"`
	RemotePort uint16 `yaml:"remote_port"`
	Domain     string `yaml:"domain"`
}

// ClientConfig contains the complete client configuration.
type ClientConfig struct {
	ClientID       string               `yaml:"client_id"`
	Transport      ClientTransportConfig `yaml:"transport"`
	LogLevel       LogLevel             `yaml:"log_level"`
	Authentication AuthenticationConfig `yaml:"authentication"`
	Proxies        []ProxyConfig        `yaml:"proxies"`
}

// TunnelConfig configures public proxy listeners owned by the server.
type TunnelConfig struct {
	BindIP            string `yaml:"bind_ip"`
	HTTPListenAddress string `yaml:"http_listen_address"`
}

// SecurityConfig configures server-side source filtering.
type SecurityConfig struct {
	IPDenyFile        string `yaml:"ip_deny_file"`
	HTTPClientIPHeader string `yaml:"http_client_ip_header"`
}

// EnsureClientID generates a process-scoped client ID when none is configured.
func EnsureClientID(configuration *ClientConfig) (string, bool, error) {
	if configuration.ClientID != "" {
		return configuration.ClientID, false, nil
	}

	randomBytes := make([]byte, generatedClientIDBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", false, fmt.Errorf("generate client ID: %w", err)
	}

	clientID := "pw_c_" + base64.RawURLEncoding.EncodeToString(randomBytes)
	configuration.ClientID = clientID
	return clientID, true, nil
}

// ServerConfig contains the complete server configuration.
type ServerConfig struct {
	Transport      ServerTransportConfig `yaml:"transport"`
	Tunnel         TunnelConfig          `yaml:"tunnel"`
	HTTP           HTTPConfig            `yaml:"http"`
	UDP            UDPConfig             `yaml:"udp"`
	Security       SecurityConfig        `yaml:"security"`
	LogLevel       LogLevel              `yaml:"log_level"`
	Authentication AuthenticationConfig  `yaml:"authentication"`
}

// DefaultClient returns the client configuration used when no file exists.
func DefaultClient() ClientConfig {
	return ClientConfig{
		Transport: ClientTransportConfig{
			Type:          transport.TypeTCP,
			ServerAddress: "127.0.0.1:7000",
		},
		LogLevel: LogLevelInfo,
	}
}

// DefaultServer returns the server configuration used when no file exists.
func DefaultServer() ServerConfig {
	return ServerConfig{
		Transport: ServerTransportConfig{
			Type:          transport.TypeTCP,
			ListenAddress: "0.0.0.0:7000",
		},
		Tunnel: TunnelConfig{
			BindIP: "0.0.0.0",
		},
		LogLevel: LogLevelInfo,
		HTTP: HTTPConfig{
			ReadHeaderTimeout:               httpDefaultReadHeaderTimeout,
			GracefulShutdownTimeout:         httpDefaultGracefulShutdownTimeout,
			MaxHeaderBytes:                  httpDefaultMaxHeaderBytes,
			MaxConcurrentRequests:           httpDefaultMaxConcurrentRequests,
			MaxConcurrentRequestsPerClient:  httpDefaultMaxConcurrentRequestsPerClient,
			MaxConcurrentRequestsPerDomain:  httpDefaultMaxConcurrentRequestsPerDomain,
			MaxIdleConnections:              httpDefaultMaxIdleConnections,
			MaxIdleConnectionsPerDomain:     httpDefaultMaxIdleConnectionsPerDomain,
			MaxUpgradeConnections:           httpDefaultMaxUpgradeConnections,
			MaxUpgradeConnectionsPerClient:  httpDefaultMaxUpgradeConnectionsPerClient,
			MaxUpgradeConnectionsPerDomain:  httpDefaultMaxUpgradeConnectionsPerDomain,
			MaxConcurrentHTTP2Streams:       httpDefaultMaxConcurrentHTTP2Streams,
		},
		UDP: DefaultUDPConfig(),
	}
}

// LoadClient loads a client configuration and overlays it on safe defaults.
func LoadClient(path string, allowMissing bool) (ClientConfig, error) {
	configuration := DefaultClient()
	if err := loadYAML(path, allowMissing, &configuration); err != nil {
		return ClientConfig{}, err
	}
	if err := validateClient(configuration); err != nil {
		return ClientConfig{}, err
	}
	return configuration, nil
}

// LoadServer loads a server configuration and overlays it on safe defaults.
func LoadServer(path string, allowMissing bool) (ServerConfig, error) {
	configuration := DefaultServer()
	if err := loadYAML(path, allowMissing, &configuration); err != nil {
		return ServerConfig{}, err
	}
	if err := validateServer(configuration); err != nil {
		return ServerConfig{}, err
	}
	return configuration, nil
}

// EnsureServerToken generates a token when token mode has no configured value.
func EnsureServerToken(configuration *ServerConfig) (string, bool, error) {
	if configuration.Authentication.Token != "" {
		return configuration.Authentication.Token, false, nil
	}

	randomBytes := make([]byte, generatedTokenBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", false, fmt.Errorf("generate server token: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(randomBytes)
	configuration.Authentication.Token = token
	return token, true, nil
}

func loadYAML(path string, allowMissing bool, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open configuration %q: %w", path, err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode configuration %q: %w", path, err)
	}

	var trailingDocument any
	if err := decoder.Decode(&trailingDocument); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode configuration %q: multiple YAML documents are not allowed", path)
		}
		return fmt.Errorf("decode configuration %q: %w", path, err)
	}
	return nil
}

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
	if err := validateAuthentication(configuration.Authentication, false); err != nil {
		return err
	}
	proxyNames := make(map[string]struct{}, len(configuration.Proxies))
	for index, proxy := range configuration.Proxies {
		if proxy.Name == "" {
			return fmt.Errorf("proxies[%d].name is required", index)
		}
		if !proxyNamePattern.MatchString(proxy.Name) {
			return fmt.Errorf("proxies[%d].name has an invalid format", index)
		}
		if _, duplicate := proxyNames[proxy.Name]; duplicate {
			return fmt.Errorf("proxies[%d].name is duplicated", index)
		}
		proxyNames[proxy.Name] = struct{}{}
		switch proxy.Type {
		case "tcp", "udp":
			if proxy.Domain != "" {
				return fmt.Errorf(
					"proxies[%d].domain is not allowed for %s",
					index,
					proxy.Type,
				)
			}
			if proxy.RemotePort == 0 {
				return fmt.Errorf("proxies[%d].remote_port must be between 1 and 65535", index)
			}
		case "http":
			if proxy.RemotePort != 0 {
				return fmt.Errorf("proxies[%d].remote_port is not allowed for http", index)
			}
			if err := ValidateHTTPDomain(proxy.Domain); err != nil {
				return fmt.Errorf("proxies[%d].domain: %w", index, err)
			}
		default:
			return fmt.Errorf("proxies[%d].type must be tcp, udp, or http", index)
		}
		if proxy.LocalIP == "" {
			configuration.Proxies[index].LocalIP = "127.0.0.1"
		} else if net.ParseIP(proxy.LocalIP) == nil {
			return fmt.Errorf("proxies[%d].local_ip must be an IP address", index)
		}
		if proxy.LocalPort == 0 {
			return fmt.Errorf("proxies[%d].local_port must be between 1 and 65535", index)
		}
	}
	return nil
}

// ValidateClientID validates a configured or protocol-provided client ID.
func ValidateClientID(clientID string) error {
	if !clientIDPattern.MatchString(clientID) {
		return errors.New("client_id must contain 1 to 64 letters, digits, dots, underscores, or hyphens")
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
	if configuration.Tunnel.HTTPListenAddress != "" &&
		configuration.Tunnel.HTTPListenAddress == configuration.Transport.ListenAddress {
		return errors.New("tunnel.http_listen_address must differ from transport.listen_address")
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
		if configuration.Tunnel.HTTPListenAddress == "" {
			return errors.New(
				"security.http_client_ip_header requires tunnel.http_listen_address",
			)
		}
	}
	if configuration.Tunnel.BindIP == "" {
		return errors.New("tunnel.bind_ip is required")
	}
	if net.ParseIP(configuration.Tunnel.BindIP) == nil {
		return errors.New("tunnel.bind_ip must be an IP address")
	}
	return validateAuthentication(configuration.Authentication, true)
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

func validateAuthentication(authentication AuthenticationConfig, server bool) error {
	if authentication.Token == "" {
		if server {
			return nil
		}
		return errors.New("authentication.token is required")
	}
	if len(authentication.Token) < generatedTokenBytes {
		return fmt.Errorf("authentication.token must contain at least %d bytes", generatedTokenBytes)
	}
	return nil
}
