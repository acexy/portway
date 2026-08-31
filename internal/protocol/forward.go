package protocol

// ForwardType identifies client-listener to server-target data semantics.
type ForwardType string

const (
	// ForwardTypeTCP identifies a reliable TCP byte-stream Forward.
	ForwardTypeTCP ForwardType = "tcp"
	// ForwardTypeUDP identifies a UDP datagram Forward.
	ForwardTypeUDP ForwardType = "udp"
)

// ForwardDeclaration contains the server-visible part of one Forward.
type ForwardDeclaration struct {
	Name       string      `json:"name"`
	Type       ForwardType `json:"type"`
	TargetIP   string      `json:"target_ip"`
	TargetPort uint16      `json:"target_port"`
}

// SyncConfiguration atomically declares complete Proxy and Forward sets.
type SyncConfiguration struct {
	Revision uint64               `json:"revision"`
	Proxies  []ProxyDeclaration   `json:"proxies"`
	Forwards []ForwardDeclaration `json:"forwards"`
}

// ForwardResult identifies one Forward Binding and its current policy state.
type ForwardResult struct {
	Name      string      `json:"name"`
	Type      ForwardType `json:"type"`
	BindingID string      `json:"binding_id"`
	Active    bool        `json:"active"`
}

// SyncConfigurationResult reports an atomic configuration result.
type SyncConfigurationResult struct {
	Revision uint64          `json:"revision"`
	Status   ProxySyncStatus `json:"status"`
	Proxies  []ProxyResult   `json:"proxies"`
	Forwards []ForwardResult `json:"forwards"`
	Error    *ProxyError     `json:"error,omitempty"`
}

// RequestForwardLink asks the server to prepare a Link for one local visitor.
type RequestForwardLink struct {
	RequestID string      `json:"request_id"`
	Name      string      `json:"name"`
	Type      ForwardType `json:"type"`
	BindingID string      `json:"binding_id"`
}

// ForwardLinkOffer returns credentials for one authorized pending Link.
type ForwardLinkOffer struct {
	RequestID       string      `json:"request_id"`
	LinkID          string      `json:"link_id,omitempty"`
	Name            string      `json:"name"`
	Type            ForwardType `json:"type"`
	BindingID       string      `json:"binding_id"`
	Ticket          string      `json:"ticket,omitempty"`
	ExpiresAtUnixMS int64       `json:"expires_at_unix_ms,omitempty"`
	Error           *ProxyError `json:"error,omitempty"`
}

// CancelForwardLink cancels a client-originated pending Link.
type CancelForwardLink struct {
	LinkID string `json:"link_id"`
}

// ForwardLinkFailed reports a client-side setup failure.
type ForwardLinkFailed struct {
	LinkID string        `json:"link_id"`
	Code   LinkErrorCode `json:"code"`
}

// ForwardBindingRevoked deactivates one client-side Forward endpoint.
type ForwardBindingRevoked struct {
	Name       string      `json:"name"`
	Type       ForwardType `json:"type"`
	BindingID  string      `json:"binding_id"`
	Generation uint64      `json:"generation"`
	Reason     string      `json:"reason"`
}

// ForwardBindingActivated restores one client-side Forward endpoint.
type ForwardBindingActivated struct {
	Name       string      `json:"name"`
	Type       ForwardType `json:"type"`
	BindingID  string      `json:"binding_id"`
	Generation uint64      `json:"generation"`
}
