package protocol

import "github.com/acexy/golang-toolkit/util/coll"

// ProxyType identifies end-to-end proxy semantics carried through Portway.
type ProxyType string

const (
	// ProxyTypeTCP identifies a reliable TCP byte-stream proxy.
	ProxyTypeTCP ProxyType = "tcp"
	// ProxyTypeHTTP identifies an HTTP domain-routing proxy.
	ProxyTypeHTTP ProxyType = "http"
	// ProxyTypeUDP identifies a UDP datagram proxy.
	ProxyTypeUDP ProxyType = "udp"
)

// HTTPPublicScheme identifies one public listener allowed for an HTTP proxy.
type HTTPPublicScheme string

const (
	// HTTPPublicSchemeHTTP allows plaintext requests from the public HTTP listener.
	HTTPPublicSchemeHTTP HTTPPublicScheme = "http"
	// HTTPPublicSchemeHTTPS allows TLS-terminated requests from the public HTTPS listener.
	HTTPPublicSchemeHTTPS HTTPPublicScheme = "https"
)

// ProxyStatus identifies the effective state of one declared proxy.
type ProxyStatus string

const (
	// ProxyStatusActive indicates that a new proxy listener is active.
	ProxyStatusActive ProxyStatus = "active"
	// ProxyStatusUnchanged indicates that an existing proxy listener was retained.
	ProxyStatusUnchanged ProxyStatus = "unchanged"
)

// ProxyDeclaration contains server-visible proxy configuration.
type ProxyDeclaration struct {
	Name          string             `json:"name"`
	Type          ProxyType          `json:"type"`
	RemotePort    uint16             `json:"remote_port,omitempty"`
	Domain        string             `json:"domain,omitempty"`
	PublicSchemes []HTTPPublicScheme `json:"public_schemes,omitempty"`
}

// AllowsPublicScheme reports whether an HTTP declaration permits one listener.
func (declaration ProxyDeclaration) AllowsPublicScheme(scheme HTTPPublicScheme) bool {
	if len(declaration.PublicSchemes) == 0 {
		return scheme == HTTPPublicSchemeHTTP
	}
	return coll.SliceContains(declaration.PublicSchemes, scheme)
}

// ProxyResult describes one successfully applied proxy.
type ProxyResult struct {
	Name       string      `json:"name"`
	Status     ProxyStatus `json:"status"`
	RemotePort uint16      `json:"remote_port"`
	Domain     string      `json:"domain,omitempty"`
}
