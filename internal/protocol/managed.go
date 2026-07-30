package protocol

// ManagedProxy contains the complete server-owned client proxy configuration.
type ManagedProxy struct {
	Name       string    `json:"name"`
	Type       ProxyType `json:"type"`
	LocalIP    string    `json:"local_ip"`
	LocalPort  uint16    `json:"local_port"`
	RemotePort uint16    `json:"remote_port,omitempty"`
	Domain     string    `json:"domain,omitempty"`
}

// ManagedConfigPrepare stages one complete managed configuration generation.
type ManagedConfigPrepare struct {
	Revision uint64         `json:"revision"`
	Digest   string         `json:"digest"`
	Proxies  []ManagedProxy `json:"proxies"`
}

// ManagedConfigStatus acknowledges one managed configuration phase.
type ManagedConfigStatus struct {
	Revision uint64 `json:"revision"`
	Digest   string `json:"digest"`
}
