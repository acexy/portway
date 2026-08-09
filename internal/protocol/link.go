package protocol

// LinkStatus identifies a RoleData binding result.
type LinkStatus string

const (
	// LinkStatusAccepted indicates that the data stream is bound and ready.
	LinkStatusAccepted LinkStatus = "accepted"
	// LinkStatusRejected indicates that the data stream must be closed.
	LinkStatusRejected LinkStatus = "rejected"
)

// LinkErrorCode identifies a stable data-link failure.
type LinkErrorCode string

const (
	LinkErrorLocalDialFailed LinkErrorCode = "local_dial_failed"
	LinkErrorTransportFailed LinkErrorCode = "transport_failed"
	LinkErrorInvalidBinding  LinkErrorCode = "invalid_binding"
	LinkErrorExpired         LinkErrorCode = "link_expired"
	LinkErrorCancelled       LinkErrorCode = "link_cancelled"
)

// OpenLink asks a client to create one RoleData stream and local connection.
type OpenLink struct {
	LinkID          string    `json:"link_id"`
	ProxyName       string    `json:"proxy_name"`
	ProxyType       ProxyType `json:"proxy_type"`
	BindingID       string    `json:"binding_id"`
	Ticket          string    `json:"ticket"`
	ExpiresAtUnixMS int64     `json:"expires_at_unix_ms"`
	MaxDatagramSize uint32    `json:"max_datagram_size,omitempty"`
	WriteTimeoutMS  uint32    `json:"write_timeout_ms,omitempty"`
}

// CancelLink asks a client to cancel an unbound link.
type CancelLink struct {
	LinkID string `json:"link_id"`
	Reason string `json:"reason"`
}

// LinkFailed reports a client-side link setup failure.
type LinkFailed struct {
	LinkID string        `json:"link_id"`
	Code   LinkErrorCode `json:"code"`
}

// BindLink is the first encrypted frame on a RoleData connection.
type BindLink struct {
	ClientID  string    `json:"client_id"`
	SessionID string    `json:"session_id"`
	LinkID    string    `json:"link_id"`
	ProxyType ProxyType `json:"proxy_type"`
	BindingID string    `json:"binding_id"`
	Ticket    string    `json:"ticket"`
}

// BindResult confirms or rejects a RoleData binding.
type BindResult struct {
	LinkID string         `json:"link_id"`
	Status LinkStatus     `json:"status"`
	Error  *LinkErrorCode `json:"error,omitempty"`
}
