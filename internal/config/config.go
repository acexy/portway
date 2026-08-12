// Package config loads and validates Portway configuration files.
package config

import (
	"regexp"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
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
	maxConfigurationFileBytes   = 4 * 1024 * 1024
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
	ProxyTypes []protocol.ProxyType `yaml:"proxy_types"`
	TCP        ProxyPermission      `yaml:"tcp"`
	UDP        ProxyPermission      `yaml:"udp"`
	HTTP       HTTPPermission       `yaml:"http"`
	Limits     PermissionLimits     `yaml:"limits"`
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
	Type          protocol.ProxyType          `yaml:"type"`
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

// OperationsConfig configures the optional local operations HTTP listener.
type OperationsConfig struct {
	ListenAddress string `yaml:"listen_address"`
}

// ServerConfig contains the complete server configuration.
type ServerConfig struct {
	Transport      ServerTransportConfig      `yaml:"transport"`
	Tunnel         TunnelConfig               `yaml:"tunnel"`
	HTTP           HTTPConfig                 `yaml:"http"`
	HTTPS          HTTPSConfig                `yaml:"https"`
	UDP            UDPConfig                  `yaml:"udp"`
	Security       SecurityConfig             `yaml:"security"`
	Operations     OperationsConfig           `yaml:"operations"`
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
