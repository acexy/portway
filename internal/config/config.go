// Package config loads and validates Portway configuration files.
package config

import (
	"regexp"

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
	// ClientID identifies the authenticated client. Shared clients may omit it.
	ClientID string `yaml:"client_id"`
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

// ForwardPortPermission configures target port ranges for one protocol.
type ForwardPortPermission struct {
	PortRanges []PortRange `yaml:"port_ranges"`
}

// ForwardIPRule binds one target network to its permitted protocol ports.
type ForwardIPRule struct {
	IPRange string                `yaml:"ip_range"`
	TCP     ForwardPortPermission `yaml:"tcp"`
	UDP     ForwardPortPermission `yaml:"udp"`
}

// ForwardRules narrows the server-wide Forward target allowlist.
type ForwardRules struct {
	Rules []ForwardIPRule `yaml:"rules"`
}

// HTTPPermission configures authorized exact or single-label wildcard domains.
type HTTPPermission struct {
	PublicSchemes []protocol.HTTPPublicScheme `yaml:"public_schemes"`
	Domains       []string                    `yaml:"domains"`
}

// ProxyPermissionLimits configures per-client Proxy resource ceilings.
type ProxyPermissionLimits struct {
	MaxTotal       int `yaml:"max_total"`
	MaxTCP         int `yaml:"max_tcp"`
	MaxUDP         int `yaml:"max_udp"`
	MaxHTTP        int `yaml:"max_http"`
	MaxActiveLinks int `yaml:"max_active_links"`
}

// ForwardPermissionLimits configures per-client Forward resource ceilings.
type ForwardPermissionLimits struct {
	MaxTotal       int `yaml:"max_total"`
	MaxTCP         int `yaml:"max_tcp"`
	MaxUDP         int `yaml:"max_udp"`
	MaxActiveLinks int `yaml:"max_active_links"`
}

// GovernedProxyPermissions restricts client-declared public Proxies.
type GovernedProxyPermissions struct {
	TCP    *ProxyPermission      `yaml:"tcp"`
	UDP    *ProxyPermission      `yaml:"udp"`
	HTTP   *HTTPPermission       `yaml:"http"`
	Limits ProxyPermissionLimits `yaml:"limits"`
}

// GovernedForwardPermissions restricts client-declared Forwards.
type GovernedForwardPermissions struct {
	Rules  []ForwardIPRule         `yaml:"rules"`
	Limits ForwardPermissionLimits `yaml:"limits"`
}

// GovernedPermissions separates both traffic directions.
type GovernedPermissions struct {
	Proxies  GovernedProxyPermissions   `yaml:"proxies"`
	Forwards GovernedForwardPermissions `yaml:"forwards"`
}

// ManagedPermissions optionally narrows server-owned Forward targets.
type ManagedPermissions struct {
	Forwards ForwardRules `yaml:"forwards"`
}

// GovernedClientConfig defines one independently authenticated governed client.
type GovernedClientConfig struct {
	Authentication ClientAuthenticationConfig `yaml:"authentication"`
	Permissions    GovernedPermissions        `yaml:"permissions"`
}

// ManagedConfiguration is the complete server-owned client proxy generation.
type ManagedConfiguration struct {
	Revision uint64          `yaml:"revision"`
	Proxies  []ProxyConfig   `yaml:"proxies"`
	Forwards []ForwardConfig `yaml:"forwards"`
}

// ManagedClientConfig defines one independently authenticated managed client.
type ManagedClientConfig struct {
	Authentication ClientAuthenticationConfig `yaml:"authentication"`
	Permissions    ManagedPermissions         `yaml:"permissions"`
	Configuration  ManagedConfiguration       `yaml:"configuration"`
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

// EndpointConfig identifies one client-side IP endpoint.
type EndpointConfig struct {
	IP   string `yaml:"ip"`
	Port uint16 `yaml:"port"`
}

// ProxyPublicConfig identifies one public Proxy endpoint or HTTP route.
type ProxyPublicConfig struct {
	Port    uint16                      `yaml:"port"`
	Domain  string                      `yaml:"domain"`
	Schemes []protocol.HTTPPublicScheme `yaml:"schemes"`
}

// ProxyConfig describes one client-side Proxy.
type ProxyConfig struct {
	Name   string             `yaml:"name"`
	Type   protocol.ProxyType `yaml:"type"`
	Local  EndpointConfig     `yaml:"local"`
	Public ProxyPublicConfig  `yaml:"public"`
}

// ClientConfig contains the complete client configuration.
type ClientConfig struct {
	Transport      ClientTransportConfig      `yaml:"transport"`
	LogLevel       LogLevel                   `yaml:"log_level"`
	Authentication ClientAuthenticationConfig `yaml:"authentication"`
	Proxies        []ProxyConfig              `yaml:"proxies"`
	Forwards       []ForwardConfig            `yaml:"forwards"`
}

// ForwardConfig describes one client-side listener and server-side target.
type ForwardConfig struct {
	Name   string               `yaml:"name"`
	Type   protocol.ForwardType `yaml:"type"`
	Listen EndpointConfig       `yaml:"listen"`
	Target EndpointConfig       `yaml:"target"`
}

// HTTPSCertificateConfig maps SNI names to one public HTTPS certificate pair.
type HTTPSCertificateConfig struct {
	Domains  []string `yaml:"domains"`
	CertFile string   `yaml:"cert_file"`
	KeyFile  string   `yaml:"key_file"`
}

// HTTPSConfig configures the public HTTPS SNI certificate set.
type HTTPSConfig struct {
	ListenAddress string                   `yaml:"listen_address"`
	Certificates  []HTTPSCertificateConfig `yaml:"certificates"`
}

// HTTPProxyConfig configures the public HTTP listener and shared HTTP runtime.
// Its runtime limits also apply to TLS-terminated HTTPS traffic.
type HTTPProxyConfig struct {
	ListenAddress string `yaml:"listen_address"`
	HTTPConfig    `yaml:",inline"`
}

// ServerProxyConfig groups every server-owned public Proxy runtime setting.
type ServerProxyConfig struct {
	BindIP string            `yaml:"bind_ip"`
	HTTP   HTTPProxyConfig   `yaml:"http"`
	HTTPS  HTTPSConfig       `yaml:"https"`
	UDP    UDPConfig         `yaml:"udp"`
	Mirror ProxyMirrorConfig `yaml:"mirror"`
}

// ProxyMirrorGroupConfig defines one server-owned TCP or UDP mirror group.
type ProxyMirrorGroupConfig struct {
	Name            string                  `yaml:"name"`
	Type            protocol.ProxyType      `yaml:"type"`
	Public          ProxyMirrorPublicConfig `yaml:"public"`
	PrimaryClientID string                  `yaml:"primary_client_id"`
	ClientIDs       []string                `yaml:"client_ids"`
}

// ProxyMirrorPublicConfig defines the public ports shared by one mirror group.
type ProxyMirrorPublicConfig struct {
	PortRanges []PortRange `yaml:"port_ranges"`
}

// Ports expands the configured inclusive ranges into concrete listener ports.
func (configuration ProxyMirrorPublicConfig) Ports() []uint16 {
	ports := make([]uint16, 0)
	for _, portRange := range configuration.PortRanges {
		for port := uint32(portRange.Start); port <= uint32(portRange.End); port++ {
			ports = append(ports, uint16(port))
		}
	}
	return ports
}

// ProxyMirrorConfig separates Governed and Managed mirror authorization.
type ProxyMirrorConfig struct {
	Governed []ProxyMirrorGroupConfig `yaml:"governed"`
	Managed  []ProxyMirrorGroupConfig `yaml:"managed"`
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
	Proxies        ServerProxyConfig          `yaml:"proxies"`
	Security       SecurityConfig             `yaml:"security"`
	Operations     OperationsConfig           `yaml:"operations"`
	Forwards       ForwardServerConfig        `yaml:"forwards"`
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

// ForwardServerConfig configures the server-wide Forward safety boundary.
type ForwardServerConfig struct {
	Enabled    bool            `yaml:"enabled"`
	Rules      []ForwardIPRule `yaml:"rules"`
	UDP        UDPConfig       `yaml:"udp"`
	Configured bool            `yaml:"-"`
}

// UnmarshalYAML records that the optional forwards section was explicitly configured.
func (configuration *ForwardServerConfig) UnmarshalYAML(node *yaml.Node) error {
	type plain ForwardServerConfig
	decoded := plain(*configuration)
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*configuration = ForwardServerConfig(decoded)
	configuration.Configured = true
	return nil
}
