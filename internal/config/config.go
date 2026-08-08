// Package config loads and validates Portway configuration files.
package config

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/acexy/portway/internal/protocol"
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
	generatedTokenBytes         = 32
	generatedClientIDBytes      = 16
	maxAuthenticationFiles      = 4096
	maxAuthenticationFileBytes  = 4 * 1024 * 1024
	maxAuthenticationTotalBytes = 64 * 1024 * 1024
)

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var proxyNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var httpHeaderNamePattern = regexp.MustCompile(
	"^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$",
)

// ClientAuthenticationConfig configures the client credential.
type ClientAuthenticationConfig struct {
	// Token selects and proves the server-owned authentication record.
	Token string `yaml:"token"`
}

// ServerAuthenticationConfig configures server authentication sources.
type ServerAuthenticationConfig struct {
	// SharedToken enables the shared authentication entry.
	SharedToken *string `yaml:"shared_token"`
	// GovernedClientsPath contains per-client Token and permission files.
	GovernedClientsPath string `yaml:"governed_clients_path"`
	// ManagedClientsPath contains per-client Token and locked configuration files.
	ManagedClientsPath string `yaml:"managed_clients_path"`
}

// PortRange is one inclusive public port authorization range.
type PortRange struct {
	Start uint16 `yaml:"start"`
	End   uint16 `yaml:"end"`
}

// ProxyPermission configures public port ranges for one proxy type.
type ProxyPermission struct {
	RemotePortRanges []PortRange `yaml:"remote_port_ranges"`
}

// HTTPPermission configures authorized exact or single-label wildcard domains.
type HTTPPermission struct {
	PublicSchemes []protocol.HTTPPublicScheme `yaml:"public_schemes"`
	Domains       []string                    `yaml:"domains"`
}

// PermissionLimits configures per-client resource ceilings.
type PermissionLimits struct {
	MaxProxies     int `yaml:"max_proxies"`
	MaxTCPProxies  int `yaml:"max_tcp_proxies"`
	MaxUDPProxies  int `yaml:"max_udp_proxies"`
	MaxHTTPProxies int `yaml:"max_http_proxies"`
	MaxActiveLinks int `yaml:"max_active_links"`
}

// GovernedPermissions restricts one client's proxy declarations.
type GovernedPermissions struct {
	ProxyTypes []string         `yaml:"proxy_types"`
	TCP        ProxyPermission  `yaml:"tcp"`
	UDP        ProxyPermission  `yaml:"udp"`
	HTTP       HTTPPermission   `yaml:"http"`
	Limits     PermissionLimits `yaml:"limits"`
}

// GovernedClientConfig defines one independently authenticated governed client.
type GovernedClientConfig struct {
	ClientID    string              `yaml:"client_id"`
	Token       string              `yaml:"token"`
	Permissions GovernedPermissions `yaml:"permissions"`
}

// ManagedConfiguration is the complete server-owned client proxy generation.
type ManagedConfiguration struct {
	Revision uint64        `yaml:"revision"`
	Proxies  []ProxyConfig `yaml:"proxies"`
}

// ManagedClientConfig defines one independently authenticated managed client.
type ManagedClientConfig struct {
	ClientID      string               `yaml:"client_id"`
	Token         string               `yaml:"token"`
	Configuration ManagedConfiguration `yaml:"configuration"`
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
	Name          string                      `yaml:"name"`
	Type          string                      `yaml:"type"`
	LocalIP       string                      `yaml:"local_ip"`
	LocalPort     uint16                      `yaml:"local_port"`
	RemotePort    uint16                      `yaml:"remote_port"`
	Domain        string                      `yaml:"domain"`
	PublicSchemes []protocol.HTTPPublicScheme `yaml:"public_schemes"`
}

// ClientConfig contains the complete client configuration.
type ClientConfig struct {
	ClientID       string                     `yaml:"client_id"`
	Transport      ClientTransportConfig      `yaml:"transport"`
	LogLevel       LogLevel                   `yaml:"log_level"`
	Authentication ClientAuthenticationConfig `yaml:"authentication"`
	Proxies        []ProxyConfig              `yaml:"proxies"`
}

// TunnelConfig configures public proxy listeners owned by the server.
type TunnelConfig struct {
	BindIP             string `yaml:"bind_ip"`
	HTTPListenAddress  string `yaml:"http_listen_address"`
	HTTPSListenAddress string `yaml:"https_listen_address"`
}

// HTTPSCertificateConfig maps SNI names to one public HTTPS certificate pair.
type HTTPSCertificateConfig struct {
	Domains  []string `yaml:"domains"`
	CertFile string   `yaml:"cert_file"`
	KeyFile  string   `yaml:"key_file"`
}

// HTTPSConfig configures the public HTTPS SNI certificate set.
type HTTPSConfig struct {
	Certificates []HTTPSCertificateConfig `yaml:"certificates"`
}

// SecurityConfig configures server-side source filtering.
type SecurityConfig struct {
	IPDenyFile         string `yaml:"ip_deny_file"`
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
	Transport      ServerTransportConfig      `yaml:"transport"`
	Tunnel         TunnelConfig               `yaml:"tunnel"`
	HTTP           HTTPConfig                 `yaml:"http"`
	HTTPS          HTTPSConfig                `yaml:"https"`
	UDP            UDPConfig                  `yaml:"udp"`
	Security       SecurityConfig             `yaml:"security"`
	LogLevel       LogLevel                   `yaml:"log_level"`
	Authentication ServerAuthenticationConfig `yaml:"authentication"`
	// SourcePath is the main file used for server hot reload.
	SourcePath string `yaml:"-"`
	// SourceDigest identifies the complete main and authentication file generation.
	SourceDigest string `yaml:"-"`
	// Generation increments for every published semantic configuration change.
	Generation uint64 `yaml:"-"`
	// SharedTokenGenerated reports that an empty source value was generated at startup.
	SharedTokenGenerated bool `yaml:"-"`
	// GovernedClients and ManagedClients are validated immutable source records.
	GovernedClients map[string]GovernedClientConfig `yaml:"-"`
	ManagedClients  map[string]ManagedClientConfig  `yaml:"-"`
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
			ReadHeaderTimeout:              httpDefaultReadHeaderTimeout,
			GracefulShutdownTimeout:        httpDefaultGracefulShutdownTimeout,
			MaxHeaderBytes:                 httpDefaultMaxHeaderBytes,
			MaxConcurrentRequests:          httpDefaultMaxConcurrentRequests,
			MaxConcurrentRequestsPerClient: httpDefaultMaxConcurrentRequestsPerClient,
			MaxConcurrentRequestsPerDomain: httpDefaultMaxConcurrentRequestsPerDomain,
			MaxIdleConnections:             httpDefaultMaxIdleConnections,
			MaxIdleConnectionsPerDomain:    httpDefaultMaxIdleConnectionsPerDomain,
			MaxUpgradeConnections:          httpDefaultMaxUpgradeConnections,
			MaxUpgradeConnectionsPerClient: httpDefaultMaxUpgradeConnectionsPerClient,
			MaxUpgradeConnectionsPerDomain: httpDefaultMaxUpgradeConnectionsPerDomain,
			MaxConcurrentHTTP2Streams:      httpDefaultMaxConcurrentHTTP2Streams,
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
	initialDigest, initialExists, err := configurationFileDigest(path, allowMissing)
	if err != nil {
		return ServerConfig{}, err
	}
	if err := loadYAML(path, allowMissing, &configuration); err != nil {
		return ServerConfig{}, err
	}
	if err := validateServer(configuration); err != nil {
		return ServerConfig{}, err
	}
	if _, err := os.Stat(path); err == nil {
		configuration.SourcePath = path
	} else if !allowMissing || !errors.Is(err, os.ErrNotExist) {
		return ServerConfig{}, fmt.Errorf("stat configuration %q: %w", path, err)
	}
	before, err := serverSourceManifest(configuration)
	if err != nil {
		return ServerConfig{}, err
	}
	if initialExists && before.mainDigest != initialDigest {
		return ServerConfig{}, errors.New("configuration files changed while loading")
	}
	if err := loadServerAuthenticationFiles(&configuration); err != nil {
		return ServerConfig{}, err
	}
	if err := validateConfiguredPublicSchemeAvailability(configuration); err != nil {
		return ServerConfig{}, err
	}
	after, err := serverSourceManifest(configuration)
	if err != nil {
		return ServerConfig{}, err
	}
	if before.digest != after.digest {
		return ServerConfig{}, errors.New("configuration files changed while loading")
	}
	configuration.SourceDigest = hex.EncodeToString(after.digest[:])
	return configuration, nil
}

type sourceManifest struct {
	mainDigest [sha256.Size]byte
	digest     [sha256.Size]byte
}

func serverSourceManifest(configuration ServerConfig) (sourceManifest, error) {
	hasher := sha256.New()
	manifest := sourceManifest{}
	if configuration.SourcePath != "" {
		digest, _, err := configurationFileDigest(configuration.SourcePath, false)
		if err != nil {
			return sourceManifest{}, err
		}
		manifest.mainDigest = digest
		hasher.Write([]byte(filepath.Clean(configuration.SourcePath)))
		hasher.Write(digest[:])
	}
	baseDirectory := "."
	if configuration.SourcePath != "" {
		baseDirectory = filepath.Dir(configuration.SourcePath)
	}
	paths := []string{
		resolveConfigurationPath(baseDirectory, configuration.Authentication.GovernedClientsPath),
		resolveConfigurationPath(baseDirectory, configuration.Authentication.ManagedClientsPath),
	}
	for _, directory := range paths {
		if directory == "" {
			continue
		}
		files, err := authenticationFiles(directory)
		if err != nil {
			return sourceManifest{}, err
		}
		hasher.Write([]byte(filepath.Clean(directory)))
		for _, file := range files {
			data, err := readAuthenticationFile(file)
			if err != nil {
				return sourceManifest{}, err
			}
			digest := sha256.Sum256(data)
			hasher.Write([]byte(filepath.Base(file)))
			hasher.Write(digest[:])
		}
	}
	copy(manifest.digest[:], hasher.Sum(nil))
	return manifest, nil
}

func configurationFileDigest(
	path string,
	allowMissing bool,
) ([sha256.Size]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return [sha256.Size]byte{}, false, nil
		}
		return [sha256.Size]byte{}, false, fmt.Errorf("read configuration %q: %w", path, err)
	}
	return sha256.Sum256(data), true, nil
}

// EnsureServerToken generates a token when token mode has no configured value.
func EnsureServerToken(configuration *ServerConfig) (string, bool, error) {
	if configuration.Authentication.SharedToken != nil {
		if *configuration.Authentication.SharedToken != "" {
			return *configuration.Authentication.SharedToken, false, nil
		}
		token, err := generateToken()
		if err != nil {
			return "", false, err
		}
		configuration.Authentication.SharedToken = &token
		configuration.SharedTokenGenerated = true
		return token, true, nil
	}
	if configuration.Authentication.GovernedClientsPath != "" ||
		configuration.Authentication.ManagedClientsPath != "" {
		return "", false, nil
	}

	token, err := generateToken()
	if err != nil {
		return "", false, err
	}
	configuration.Authentication.SharedToken = &token
	configuration.SharedTokenGenerated = true
	return token, true, nil
}

func generateToken() (string, error) {
	randomBytes := make([]byte, generatedTokenBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate server token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
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
	return decodeYAML(path, file, destination)
}

func decodeYAML(path string, reader io.Reader, destination any) error {
	decoder := yaml.NewDecoder(reader)
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

func loadAuthenticationYAML(path string, destination any) error {
	data, err := readAuthenticationFile(path)
	if err != nil {
		return err
	}
	return decodeYAML(path, bytes.NewReader(data), destination)
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
			if proxy.Type != "http" {
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
		if proxy.Name == "" || !proxyNamePattern.MatchString(proxy.Name) {
			return fmt.Errorf("%s[%d].name has an invalid format", field, index)
		}
		if _, duplicate := names[proxy.Name]; duplicate {
			return fmt.Errorf("%s[%d].name is duplicated", field, index)
		}
		names[proxy.Name] = struct{}{}
		switch proxy.Type {
		case "tcp":
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
		case "udp":
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
		case "http":
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
