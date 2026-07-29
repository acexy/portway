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
	"time"

	"gopkg.in/yaml.v3"

	"github.com/acexy/portway/internal/consts"
)

// AuthenticationMode selects how client and server connections are protected.
type AuthenticationMode string

// LogLevel selects the minimum severity emitted by the process logger.
type LogLevel string

const (
	// AuthenticationModeToken uses a shared static token.
	AuthenticationModeToken AuthenticationMode = "token"
	// AuthenticationModeTLS reserves mutual TLS for a future implementation.
	AuthenticationModeTLS AuthenticationMode = "tls"
)

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

// TLSConfig contains the certificate files required by either endpoint.
type TLSConfig struct {
	CAFile       string `yaml:"ca_file"`
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	ServerName   string `yaml:"server_name"`
	ClientCAFile string `yaml:"client_ca_file"`
}

// AuthenticationConfig configures connection authentication and encryption.
type AuthenticationConfig struct {
	Mode  AuthenticationMode `yaml:"mode"`
	Token string             `yaml:"token"`
	TLS   *TLSConfig         `yaml:"tls"`
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
	ServerAddress  string               `yaml:"server_address"`
	LogLevel       LogLevel             `yaml:"log_level"`
	Authentication AuthenticationConfig `yaml:"authentication"`
	Proxies        []ProxyConfig        `yaml:"proxies"`
}

// HTTPConfig configures the public HTTP server and its bounded resources.
type HTTPConfig struct {
	ReadHeaderTimeout                time.Duration `yaml:"read_header_timeout"`
	GracefulShutdownTimeout          time.Duration `yaml:"graceful_shutdown_timeout"`
	IdleConnectionTimeout            time.Duration `yaml:"idle_connection_timeout"`
	ResponseHeaderTimeout            time.Duration `yaml:"response_header_timeout"`
	MaxHeaderBytes                   int           `yaml:"max_header_bytes"`
	MaxConcurrentRequests            int           `yaml:"max_concurrent_requests"`
	MaxConcurrentRequestsPerClient   int           `yaml:"max_concurrent_requests_per_client"`
	MaxConcurrentRequestsPerDomain   int           `yaml:"max_concurrent_requests_per_domain"`
	MaxIdleConnections               int           `yaml:"max_idle_connections"`
	MaxIdleConnectionsPerDomain      int           `yaml:"max_idle_connections_per_domain"`
	MaxUpgradeConnections            int           `yaml:"max_upgrade_connections"`
	MaxUpgradeConnectionsPerClient   int           `yaml:"max_upgrade_connections_per_client"`
	MaxUpgradeConnectionsPerDomain   int           `yaml:"max_upgrade_connections_per_domain"`
	MaxConcurrentHTTP2Streams        int           `yaml:"max_concurrent_http2_streams"`
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
	ListenAddress  string               `yaml:"listen_address"`
	HTTPListenAddress string            `yaml:"http_listen_address"`
	HTTP               HTTPConfig       `yaml:"http"`
	ProxyBindIP    string               `yaml:"proxy_bind_ip"`
	LogLevel       LogLevel             `yaml:"log_level"`
	Authentication AuthenticationConfig `yaml:"authentication"`
}

// DefaultClient returns the client configuration used when no file exists.
func DefaultClient() ClientConfig {
	return ClientConfig{
		ServerAddress: "127.0.0.1:7000",
		LogLevel:      LogLevelInfo,
		Authentication: AuthenticationConfig{
			Mode: AuthenticationModeToken,
		},
	}
}

// DefaultServer returns the server configuration used when no file exists.
func DefaultServer() ServerConfig {
	return ServerConfig{
		ListenAddress: "0.0.0.0:7000",
		ProxyBindIP:   "0.0.0.0",
		LogLevel:      LogLevelInfo,
		HTTP: HTTPConfig{
			ReadHeaderTimeout:               consts.HTTPDefaultReadHeaderTimeout,
			GracefulShutdownTimeout:         consts.HTTPDefaultGracefulShutdownTimeout,
			MaxHeaderBytes:                  consts.HTTPDefaultMaxHeaderBytes,
			MaxConcurrentRequests:           consts.HTTPDefaultMaxConcurrentRequests,
			MaxConcurrentRequestsPerClient:  consts.HTTPDefaultMaxConcurrentRequestsPerClient,
			MaxConcurrentRequestsPerDomain:  consts.HTTPDefaultMaxConcurrentRequestsPerDomain,
			MaxIdleConnections:              consts.HTTPDefaultMaxIdleConnections,
			MaxIdleConnectionsPerDomain:     consts.HTTPDefaultMaxIdleConnectionsPerDomain,
			MaxUpgradeConnections:           consts.HTTPDefaultMaxUpgradeConnections,
			MaxUpgradeConnectionsPerClient:  consts.HTTPDefaultMaxUpgradeConnectionsPerClient,
			MaxUpgradeConnectionsPerDomain:  consts.HTTPDefaultMaxUpgradeConnectionsPerDomain,
			MaxConcurrentHTTP2Streams:       consts.HTTPDefaultMaxConcurrentHTTP2Streams,
		},
		Authentication: AuthenticationConfig{
			Mode: AuthenticationModeToken,
		},
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
	if configuration.Authentication.Mode != AuthenticationModeToken ||
		configuration.Authentication.Token != "" {
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
	if configuration.ServerAddress == "" {
		return errors.New("server_address is required")
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
		case "tcp":
			if proxy.Domain != "" {
				return fmt.Errorf("proxies[%d].domain is not allowed for tcp", index)
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
			return fmt.Errorf("proxies[%d].type must be tcp or http", index)
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
	if configuration.ListenAddress == "" {
		return errors.New("listen_address is required")
	}
	if configuration.HTTPListenAddress != "" &&
		configuration.HTTPListenAddress == configuration.ListenAddress {
		return errors.New("http_listen_address must differ from listen_address")
	}
	if err := validateHTTPConfig(configuration.HTTP); err != nil {
		return err
	}
	if configuration.ProxyBindIP == "" {
		return errors.New("proxy_bind_ip is required")
	}
	if net.ParseIP(configuration.ProxyBindIP) == nil {
		return errors.New("proxy_bind_ip must be an IP address")
	}
	return validateAuthentication(configuration.Authentication, true)
}

func validateHTTPConfig(configuration HTTPConfig) error {
	if configuration.ReadHeaderTimeout <= 0 ||
		configuration.ReadHeaderTimeout > consts.HTTPHardMaxReadHeaderTimeout {
		return fmt.Errorf("http.read_header_timeout must be greater than zero and at most %s", consts.HTTPHardMaxReadHeaderTimeout)
	}
	if configuration.GracefulShutdownTimeout <= 0 ||
		configuration.GracefulShutdownTimeout > consts.HTTPHardMaxGracefulShutdownTimeout {
		return fmt.Errorf("http.graceful_shutdown_timeout must be greater than zero and at most %s", consts.HTTPHardMaxGracefulShutdownTimeout)
	}
	for name, value := range map[string]time.Duration{
		"idle_connection_timeout": configuration.IdleConnectionTimeout,
		"response_header_timeout":  configuration.ResponseHeaderTimeout,
	} {
		if value < 0 || value > consts.HTTPHardMaxBusinessTimeout {
			return fmt.Errorf("http.%s must be zero or at most %s", name, consts.HTTPHardMaxBusinessTimeout)
		}
	}
	limits := []struct {
		name  string
		value int
		max   int
	}{
		{"max_header_bytes", configuration.MaxHeaderBytes, consts.HTTPHardMaxHeaderBytes},
		{"max_concurrent_requests", configuration.MaxConcurrentRequests, consts.HTTPHardMaxConcurrentRequests},
		{"max_concurrent_requests_per_client", configuration.MaxConcurrentRequestsPerClient, consts.HTTPHardMaxConcurrentRequestsPerClient},
		{"max_concurrent_requests_per_domain", configuration.MaxConcurrentRequestsPerDomain, consts.HTTPHardMaxConcurrentRequestsPerDomain},
		{"max_idle_connections", configuration.MaxIdleConnections, consts.HTTPHardMaxIdleConnections},
		{"max_idle_connections_per_domain", configuration.MaxIdleConnectionsPerDomain, consts.HTTPHardMaxIdleConnectionsPerDomain},
		{"max_upgrade_connections", configuration.MaxUpgradeConnections, consts.HTTPHardMaxUpgradeConnections},
		{"max_upgrade_connections_per_client", configuration.MaxUpgradeConnectionsPerClient, consts.HTTPHardMaxUpgradeConnectionsPerClient},
		{"max_upgrade_connections_per_domain", configuration.MaxUpgradeConnectionsPerDomain, consts.HTTPHardMaxUpgradeConnectionsPerDomain},
		{"max_concurrent_http2_streams", configuration.MaxConcurrentHTTP2Streams, consts.HTTPHardMaxConcurrentHTTP2Streams},
	}
	for _, limit := range limits {
		if limit.value <= 0 || limit.value > limit.max {
			return fmt.Errorf("http.%s must be greater than zero and at most %d", limit.name, limit.max)
		}
	}
	if configuration.MaxConcurrentRequestsPerClient > configuration.MaxConcurrentRequests ||
		configuration.MaxConcurrentRequestsPerDomain > configuration.MaxConcurrentRequests ||
		configuration.MaxIdleConnectionsPerDomain > configuration.MaxIdleConnections ||
		configuration.MaxUpgradeConnectionsPerClient > configuration.MaxUpgradeConnections ||
		configuration.MaxUpgradeConnectionsPerDomain > configuration.MaxUpgradeConnections {
		return errors.New("HTTP per-client and per-domain limits must not exceed their global limits")
	}
	return nil
}

// ValidateHTTPDomain validates a canonical HTTP proxy domain.
func ValidateHTTPDomain(domain string) error {
	if domain == "" || len(domain) > 253 || domain != strings.ToLower(domain) ||
		strings.HasSuffix(domain, ".") || net.ParseIP(domain) != nil ||
		strings.ContainsAny(domain, ":/*") {
		return errors.New("must be a canonical lowercase ASCII DNS name without port, path, wildcard, or trailing dot")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("contains an invalid DNS label")
		}
		for _, character := range label {
			if character > 127 ||
				!((character >= 'a' && character <= 'z') ||
					(character >= '0' && character <= '9') ||
					character == '-') {
				return errors.New("contains an invalid DNS label")
			}
		}
	}
	return nil
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
	switch authentication.Mode {
	case AuthenticationModeToken:
		if authentication.Token != "" && len(authentication.Token) < generatedTokenBytes {
			return fmt.Errorf("authentication.token must contain at least %d bytes", generatedTokenBytes)
		}
		return nil
	case AuthenticationModeTLS:
		if authentication.TLS == nil {
			return errors.New("authentication.tls is required when mode is tls")
		}
		if authentication.TLS.CertFile == "" {
			return errors.New("authentication.tls.cert_file is required when mode is tls")
		}
		if authentication.TLS.KeyFile == "" {
			return errors.New("authentication.tls.key_file is required when mode is tls")
		}
		if server {
			if authentication.TLS.ClientCAFile == "" {
				return errors.New("authentication.tls.client_ca_file is required on the server")
			}
		} else {
			if authentication.TLS.CAFile == "" {
				return errors.New("authentication.tls.ca_file is required on the client")
			}
			if authentication.TLS.ServerName == "" {
				return errors.New("authentication.tls.server_name is required on the client")
			}
		}
		return errors.New("authentication mode tls is not implemented")
	default:
		return fmt.Errorf("authentication.mode must be token or tls, got %q", authentication.Mode)
	}
}
