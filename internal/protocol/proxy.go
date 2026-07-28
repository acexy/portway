package protocol

// ProxyType identifies a supported proxy protocol.
type ProxyType string

const (
	// ProxyTypeTCP identifies a reliable TCP byte-stream proxy.
	ProxyTypeTCP ProxyType = "tcp"
)

// ProxySyncStatus identifies the result of an atomic proxy declaration.
type ProxySyncStatus string

const (
	// ProxySyncStatusApplied indicates that the complete declaration is active.
	ProxySyncStatusApplied ProxySyncStatus = "applied"
	// ProxySyncStatusRejected indicates that no part of the declaration was applied.
	ProxySyncStatusRejected ProxySyncStatus = "rejected"
)

// ProxyStatus identifies the effective state of one declared proxy.
type ProxyStatus string

const (
	// ProxyStatusActive indicates that a new proxy listener is active.
	ProxyStatusActive ProxyStatus = "active"
	// ProxyStatusUnchanged indicates that an existing proxy listener was retained.
	ProxyStatusUnchanged ProxyStatus = "unchanged"
)

// ProxyErrorCode identifies a permanent proxy registration failure.
type ProxyErrorCode string

const (
	ProxyErrorInvalidRequest   ProxyErrorCode = "invalid_request"
	ProxyErrorInvalidProxy     ProxyErrorCode = "invalid_proxy"
	ProxyErrorPortConflict     ProxyErrorCode = "port_conflict"
	ProxyErrorCapacityExceeded ProxyErrorCode = "capacity_exceeded"
	ProxyErrorSessionInactive  ProxyErrorCode = "session_inactive"
	ProxyErrorListenerFailed   ProxyErrorCode = "listener_failed"
)

// ProxyDeclaration contains server-visible proxy configuration.
type ProxyDeclaration struct {
	Name       string    `json:"name"`
	Type       ProxyType `json:"type"`
	RemotePort uint16    `json:"remote_port"`
}

// SyncProxies atomically declares the complete proxy set for one session.
type SyncProxies struct {
	Revision uint64             `json:"revision"`
	Proxies  []ProxyDeclaration `json:"proxies"`
}

// ProxyResult describes one successfully applied proxy.
type ProxyResult struct {
	Name       string      `json:"name"`
	Status     ProxyStatus `json:"status"`
	RemotePort uint16      `json:"remote_port"`
}

// ProxyError describes a stable proxy registration failure.
type ProxyError struct {
	Code      ProxyErrorCode `json:"code"`
	Message   string         `json:"message"`
	ProxyName string         `json:"proxy_name,omitempty"`
	Retryable bool           `json:"retryable"`
}

// SyncResult reports an atomic proxy declaration result.
type SyncResult struct {
	Revision uint64          `json:"revision"`
	Status   ProxySyncStatus `json:"status"`
	Proxies  []ProxyResult   `json:"proxies"`
	Error    *ProxyError     `json:"error,omitempty"`
}
