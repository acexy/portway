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
	"sort"
	"strings"

	"github.com/acexy/portway/internal/authentication"
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
	Domains []string `yaml:"domains"`
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
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	LocalIP    string `yaml:"local_ip"`
	LocalPort  uint16 `yaml:"local_port"`
	RemotePort uint16 `yaml:"remote_port"`
	Domain     string `yaml:"domain"`
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
	BindIP            string `yaml:"bind_ip"`
	HTTPListenAddress string `yaml:"http_listen_address"`
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

// BuildAuthenticationSnapshot builds the immutable runtime authentication index.
func BuildAuthenticationSnapshot(configuration ServerConfig) (*authentication.Snapshot, error) {
	records := make(
		[]authentication.Record,
		0,
		1+len(configuration.GovernedClients)+len(configuration.ManagedClients),
	)
	sharedToken := ""
	if configuration.Authentication.SharedToken != nil {
		sharedToken = *configuration.Authentication.SharedToken
	}
	if sharedToken != "" {
		records = append(records, authentication.Record{
			Context: authentication.Context{Mode: authentication.ModeShared},
			Token:   sharedToken,
		})
	}
	for _, client := range configuration.GovernedClients {
		records = append(records, authentication.Record{
			Context: authentication.Context{
				Mode:     authentication.ModeGoverned,
				ClientID: client.ClientID,
			},
			Token: client.Token,
		})
	}
	for _, client := range configuration.ManagedClients {
		records = append(records, authentication.Record{
			Context: authentication.Context{
				Mode:     authentication.ModeManaged,
				ClientID: client.ClientID,
			},
			Token: client.Token,
		})
	}
	return authentication.NewSnapshot(records)
}

func loadServerAuthenticationFiles(configuration *ServerConfig) error {
	baseDirectory := "."
	if configuration.SourcePath != "" {
		baseDirectory = filepath.Dir(configuration.SourcePath)
	}
	governedClients, err := loadGovernedClients(
		resolveConfigurationPath(baseDirectory, configuration.Authentication.GovernedClientsPath),
	)
	if err != nil {
		return err
	}
	managedClients, err := loadManagedClients(
		resolveConfigurationPath(baseDirectory, configuration.Authentication.ManagedClientsPath),
	)
	if err != nil {
		return err
	}
	for clientID := range governedClients {
		if _, duplicate := managedClients[clientID]; duplicate {
			return fmt.Errorf("client_id %q is configured in both governed and managed modes", clientID)
		}
	}
	configuration.GovernedClients = governedClients
	configuration.ManagedClients = managedClients
	if _, err := BuildAuthenticationSnapshot(*configuration); err != nil {
		return err
	}
	return nil
}

func resolveConfigurationPath(baseDirectory string, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDirectory, path)
}

func loadGovernedClients(path string) (map[string]GovernedClientConfig, error) {
	clients := make(map[string]GovernedClientConfig)
	if path == "" {
		return clients, nil
	}
	files, err := authenticationFiles(path)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		client := GovernedClientConfig{
			Permissions: GovernedPermissions{
				Limits: DefaultPermissionLimits(),
			},
		}
		if err := loadAuthenticationYAML(file, &client); err != nil {
			return nil, err
		}
		if err := validateAuthenticationClientFile(file, client.ClientID, client.Token); err != nil {
			return nil, err
		}
		if err := validateGovernedPermissions(client.Permissions); err != nil {
			return nil, fmt.Errorf("validate governed client %q: %w", client.ClientID, err)
		}
		if _, duplicate := clients[client.ClientID]; duplicate {
			return nil, fmt.Errorf("client_id %q is duplicated", client.ClientID)
		}
		clients[client.ClientID] = client
	}
	return clients, nil
}

func loadManagedClients(path string) (map[string]ManagedClientConfig, error) {
	clients := make(map[string]ManagedClientConfig)
	if path == "" {
		return clients, nil
	}
	files, err := authenticationFiles(path)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		var client ManagedClientConfig
		if err := loadAuthenticationYAML(file, &client); err != nil {
			return nil, err
		}
		if err := validateAuthenticationClientFile(file, client.ClientID, client.Token); err != nil {
			return nil, err
		}
		if client.Configuration.Revision == 0 {
			return nil, fmt.Errorf(
				"validate managed client %q: configuration.revision must be greater than zero",
				client.ClientID,
			)
		}
		if err := validateManagedProxies(client.Configuration.Proxies); err != nil {
			return nil, fmt.Errorf("validate managed client %q: %w", client.ClientID, err)
		}
		if _, duplicate := clients[client.ClientID]; duplicate {
			return nil, fmt.Errorf("client_id %q is duplicated", client.ClientID)
		}
		clients[client.ClientID] = client
	}
	if err := validateManagedClientConflicts(clients); err != nil {
		return nil, err
	}
	return clients, nil
}

func authenticationFiles(path string) ([]string, error) {
	directoryInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect authentication directory %q: %w", path, err)
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return nil, fmt.Errorf(
			"authentication directory %q must be a directory without symbolic links",
			path,
		)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read authentication directory %q: %w", path, err)
	}
	files := make([]string, 0, len(entries))
	var totalBytes int64
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil, fmt.Errorf(
				"authentication file %q must be a regular file without symbolic links",
				filepath.Join(path, entry.Name()),
			)
		}
		if len(files) >= maxAuthenticationFiles {
			return nil, fmt.Errorf(
				"authentication directory %q exceeds %d YAML files",
				path,
				maxAuthenticationFiles,
			)
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect authentication file %q: %w", entry.Name(), err)
		}
		if info.Size() > maxAuthenticationFileBytes {
			return nil, fmt.Errorf(
				"authentication file %q exceeds %d bytes",
				entry.Name(),
				maxAuthenticationFileBytes,
			)
		}
		totalBytes += info.Size()
		if totalBytes > maxAuthenticationTotalBytes {
			return nil, fmt.Errorf(
				"authentication directory %q exceeds %d total bytes",
				path,
				maxAuthenticationTotalBytes,
			)
		}
		files = append(files, filepath.Join(path, entry.Name()))
	}
	sort.Strings(files)
	return files, nil
}

func readAuthenticationFile(path string) ([]byte, error) {
	directory := filepath.Dir(path)
	name := filepath.Base(path)
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open authentication directory %q: %w", directory, err)
	}
	defer root.Close()

	before, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect authentication file %q: %w", path, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf(
			"authentication file %q must be a regular file without symbolic links",
			path,
		)
	}
	if before.Size() > maxAuthenticationFileBytes {
		return nil, fmt.Errorf(
			"authentication file %q exceeds %d bytes",
			name,
			maxAuthenticationFileBytes,
		)
	}

	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open authentication file %q: %w", path, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened authentication file %q: %w", path, err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("authentication file %q changed while opening", path)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxAuthenticationFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read authentication file %q: %w", path, err)
	}
	if len(data) > maxAuthenticationFileBytes {
		return nil, fmt.Errorf(
			"authentication file %q exceeds %d bytes",
			name,
			maxAuthenticationFileBytes,
		)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect read authentication file %q: %w", path, err)
	}
	if !os.SameFile(opened, after) || opened.Size() != after.Size() ||
		!opened.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("authentication file %q changed while reading", path)
	}
	return data, nil
}

func validateAuthenticationClientFile(path string, clientID string, token string) error {
	if err := ValidateClientID(clientID); err != nil {
		return fmt.Errorf("validate authentication file %q: %w", path, err)
	}
	if len(token) < generatedTokenBytes {
		return fmt.Errorf(
			"authentication file %q token must contain at least %d bytes",
			path,
			generatedTokenBytes,
		)
	}
	return nil
}

type managedBindingOwner struct {
	clientID  string
	proxyName string
}

func validateManagedClientConflicts(clients map[string]ManagedClientConfig) error {
	clientIDs := make([]string, 0, len(clients))
	for clientID := range clients {
		clientIDs = append(clientIDs, clientID)
	}
	sort.Strings(clientIDs)

	tcpPorts := make(map[uint16]managedBindingOwner)
	udpPorts := make(map[uint16]managedBindingOwner)
	httpDomains := make(map[string]managedBindingOwner)
	for _, clientID := range clientIDs {
		for _, proxy := range clients[clientID].Configuration.Proxies {
			owner := managedBindingOwner{
				clientID:  clientID,
				proxyName: proxy.Name,
			}
			switch proxy.Type {
			case "tcp":
				if previous, exists := tcpPorts[proxy.RemotePort]; exists {
					return managedBindingConflict(
						"TCP remote port",
						fmt.Sprint(proxy.RemotePort),
						previous,
						owner,
					)
				}
				tcpPorts[proxy.RemotePort] = owner
			case "udp":
				if previous, exists := udpPorts[proxy.RemotePort]; exists {
					return managedBindingConflict(
						"UDP remote port",
						fmt.Sprint(proxy.RemotePort),
						previous,
						owner,
					)
				}
				udpPorts[proxy.RemotePort] = owner
			case "http":
				if previous, exists := httpDomains[proxy.Domain]; exists {
					return managedBindingConflict(
						"HTTP domain",
						proxy.Domain,
						previous,
						owner,
					)
				}
				httpDomains[proxy.Domain] = owner
			}
		}
	}
	return nil
}

func managedBindingConflict(
	resource string,
	value string,
	first managedBindingOwner,
	second managedBindingOwner,
) error {
	return fmt.Errorf(
		"managed %s %q is configured by client %q proxy %q and client %q proxy %q",
		resource,
		value,
		first.clientID,
		first.proxyName,
		second.clientID,
		second.proxyName,
	)
}

func validateGovernedPermissions(permissions GovernedPermissions) error {
	types := make(map[string]struct{}, len(permissions.ProxyTypes))
	for _, proxyType := range permissions.ProxyTypes {
		switch proxyType {
		case "tcp", "udp", "http":
		default:
			return fmt.Errorf("permissions.proxy_types contains unsupported type %q", proxyType)
		}
		if _, duplicate := types[proxyType]; duplicate {
			return fmt.Errorf("permissions.proxy_types contains duplicate type %q", proxyType)
		}
		types[proxyType] = struct{}{}
	}
	if err := validatePortRanges("permissions.tcp.remote_port_ranges", permissions.TCP.RemotePortRanges); err != nil {
		return err
	}
	if err := validatePortRanges("permissions.udp.remote_port_ranges", permissions.UDP.RemotePortRanges); err != nil {
		return err
	}
	for index, domain := range permissions.HTTP.Domains {
		if strings.HasPrefix(domain, "*.") {
			if err := ValidateHTTPDomain(strings.TrimPrefix(domain, "*.")); err != nil {
				return fmt.Errorf("permissions.http.domains[%d]: invalid wildcard domain", index)
			}
			continue
		}
		if err := ValidateHTTPDomain(domain); err != nil {
			return fmt.Errorf("permissions.http.domains[%d]: %w", index, err)
		}
	}
	limits := permissions.Limits
	for _, limit := range []struct {
		name  string
		value int
		max   int
	}{
		{"max_proxies", limits.MaxProxies, hardMaxProxiesPerClient},
		{"max_tcp_proxies", limits.MaxTCPProxies, hardMaxProxiesPerClient},
		{"max_udp_proxies", limits.MaxUDPProxies, hardMaxProxiesPerClient},
		{"max_http_proxies", limits.MaxHTTPProxies, hardMaxProxiesPerClient},
		{"max_active_links", limits.MaxActiveLinks, hardMaxActiveLinksPerClient},
	} {
		if limit.value <= 0 || limit.value > limit.max {
			return fmt.Errorf(
				"permissions.limits.%s must be greater than zero and at most %d",
				limit.name,
				limit.max,
			)
		}
	}
	if limits.MaxTCPProxies > limits.MaxProxies ||
		limits.MaxUDPProxies > limits.MaxProxies ||
		limits.MaxHTTPProxies > limits.MaxProxies {
		return errors.New(
			"permissions per-type proxy limits must not exceed max_proxies",
		)
	}
	if err := validateGovernedRulePresence(
		"tcp",
		types,
		len(permissions.TCP.RemotePortRanges),
		"permissions.tcp.remote_port_ranges",
	); err != nil {
		return err
	}
	if err := validateGovernedRulePresence(
		"udp",
		types,
		len(permissions.UDP.RemotePortRanges),
		"permissions.udp.remote_port_ranges",
	); err != nil {
		return err
	}
	if err := validateGovernedRulePresence(
		"http",
		types,
		len(permissions.HTTP.Domains),
		"permissions.http.domains",
	); err != nil {
		return err
	}
	return nil
}

func validateGovernedRulePresence(
	proxyType string,
	allowedTypes map[string]struct{},
	ruleCount int,
	field string,
) error {
	_, allowed := allowedTypes[proxyType]
	if allowed && ruleCount == 0 {
		return fmt.Errorf("%s must not be empty when %s is allowed", field, proxyType)
	}
	if !allowed && ruleCount != 0 {
		return fmt.Errorf("%s must be empty when %s is not allowed", field, proxyType)
	}
	return nil
}

func validatePortRanges(field string, ranges []PortRange) error {
	sortedRanges := append([]PortRange(nil), ranges...)
	sort.Slice(sortedRanges, func(left int, right int) bool {
		return sortedRanges[left].Start < sortedRanges[right].Start
	})
	var previousEnd uint16
	for index, portRange := range sortedRanges {
		if portRange.Start == 0 || portRange.End == 0 || portRange.Start > portRange.End {
			return fmt.Errorf("%s[%d] is invalid", field, index)
		}
		if index > 0 && portRange.Start <= previousEnd {
			return fmt.Errorf("%s contains overlapping ranges", field)
		}
		previousEnd = portRange.End
	}
	return nil
}

func validateManagedProxies(proxies []ProxyConfig) error {
	if len(proxies) > hardMaxProxiesPerClient {
		return fmt.Errorf(
			"configuration.proxies must contain at most %d entries",
			hardMaxProxiesPerClient,
		)
	}
	names := make(map[string]struct{}, len(proxies))
	tcpPorts := make(map[uint16]struct{})
	udpPorts := make(map[uint16]struct{})
	httpDomains := make(map[string]struct{})
	for index, proxy := range proxies {
		if proxy.Name == "" || !proxyNamePattern.MatchString(proxy.Name) {
			return fmt.Errorf("configuration.proxies[%d].name has an invalid format", index)
		}
		if _, duplicate := names[proxy.Name]; duplicate {
			return fmt.Errorf("configuration.proxies[%d].name is duplicated", index)
		}
		names[proxy.Name] = struct{}{}
		switch proxy.Type {
		case "tcp":
			if proxy.RemotePort == 0 || proxy.Domain != "" {
				return fmt.Errorf("configuration.proxies[%d] has invalid %s fields", index, proxy.Type)
			}
			if _, duplicate := tcpPorts[proxy.RemotePort]; duplicate {
				return fmt.Errorf(
					"configuration.proxies[%d].remote_port is duplicated for tcp",
					index,
				)
			}
			tcpPorts[proxy.RemotePort] = struct{}{}
		case "udp":
			if proxy.RemotePort == 0 || proxy.Domain != "" {
				return fmt.Errorf("configuration.proxies[%d] has invalid %s fields", index, proxy.Type)
			}
			if _, duplicate := udpPorts[proxy.RemotePort]; duplicate {
				return fmt.Errorf(
					"configuration.proxies[%d].remote_port is duplicated for udp",
					index,
				)
			}
			udpPorts[proxy.RemotePort] = struct{}{}
		case "http":
			if proxy.RemotePort != 0 {
				return fmt.Errorf("configuration.proxies[%d].remote_port is not allowed for http", index)
			}
			if err := ValidateHTTPDomain(proxy.Domain); err != nil {
				return fmt.Errorf("configuration.proxies[%d].domain: %w", index, err)
			}
			if _, duplicate := httpDomains[proxy.Domain]; duplicate {
				return fmt.Errorf(
					"configuration.proxies[%d].domain is duplicated",
					index,
				)
			}
			httpDomains[proxy.Domain] = struct{}{}
		default:
			return fmt.Errorf("configuration.proxies[%d].type is invalid", index)
		}
		if net.ParseIP(proxy.LocalIP) == nil || proxy.LocalPort == 0 {
			return fmt.Errorf("configuration.proxies[%d] has invalid local target", index)
		}
	}
	return nil
}

// ValidateManagedProxies validates a complete server-owned client proxy set.
func ValidateManagedProxies(proxies []ProxyConfig) error {
	return validateManagedProxies(proxies)
}
