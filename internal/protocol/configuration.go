package protocol

// ConfigurationSyncStatus identifies the atomic combined configuration outcome.
type ConfigurationSyncStatus string

const (
	ConfigurationSyncStatusApplied  ConfigurationSyncStatus = "applied"
	ConfigurationSyncStatusRejected ConfigurationSyncStatus = "rejected"
)

// ConfigurationResourceKind identifies the rejected collection member.
type ConfigurationResourceKind string

const (
	ConfigurationResourceProxy   ConfigurationResourceKind = "proxy"
	ConfigurationResourceForward ConfigurationResourceKind = "forward"
)

// ConfigurationErrorCode identifies an atomic configuration rejection.
type ConfigurationErrorCode string

const (
	ConfigurationErrorProxyTypeNotAllowed   ConfigurationErrorCode = "proxy_type_not_allowed"
	ConfigurationErrorForwardTypeNotAllowed ConfigurationErrorCode = "forward_type_not_allowed"
)

// ConfigurationError describes an atomic Proxy/Forward configuration rejection.
type ConfigurationError struct {
	Code         ConfigurationErrorCode    `json:"code"`
	Message      string                    `json:"message"`
	ResourceKind ConfigurationResourceKind `json:"resource_kind,omitempty"`
	ResourceName string                    `json:"resource_name,omitempty"`
	Retryable    bool                      `json:"retryable"`
}

// SyncConfiguration atomically declares complete Proxy and Forward sets.
type SyncConfiguration struct {
	Revision uint64               `json:"revision"`
	Proxies  []ProxyDeclaration   `json:"proxies"`
	Forwards []ForwardDeclaration `json:"forwards"`
}

// SyncConfigurationResult reports an atomic configuration result.
type SyncConfigurationResult struct {
	Revision uint64                  `json:"revision"`
	Status   ConfigurationSyncStatus `json:"status"`
	Proxies  []ProxyResult           `json:"proxies"`
	Forwards []ForwardResult         `json:"forwards"`
	Error    *ConfigurationError     `json:"error,omitempty"`
}
