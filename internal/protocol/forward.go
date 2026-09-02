package protocol

import "time"

// ForwardType identifies client-listener to server-target data semantics.
type ForwardType string

// ForwardErrorCode identifies a stable Forward declaration or offer failure.
type ForwardErrorCode string

const (
	ForwardErrorInvalidRequest   ForwardErrorCode = "invalid_request"
	ForwardErrorInvalidForward   ForwardErrorCode = "invalid_forward"
	ForwardErrorSessionInactive  ForwardErrorCode = "session_inactive"
	ForwardErrorTargetNotAllowed ForwardErrorCode = "forward_target_not_allowed"
	ForwardErrorLimitExceeded    ForwardErrorCode = "forward_limit_exceeded"
	ForwardErrorBindingInvalid   ForwardErrorCode = "forward_binding_invalid"
)

// ForwardError describes a Forward-specific declaration or offer failure.
type ForwardError struct {
	Code        ForwardErrorCode `json:"code"`
	Message     string           `json:"message"`
	ForwardName string           `json:"forward_name,omitempty"`
	Retryable   bool             `json:"retryable"`
}

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

// ForwardResult identifies one Forward Binding and its current policy state.
type ForwardResult struct {
	Name      string            `json:"name"`
	Type      ForwardType       `json:"type"`
	BindingID string            `json:"binding_id"`
	Active    bool              `json:"active"`
	UDP       *ForwardUDPConfig `json:"udp,omitempty"`
}

// ForwardUDPConfig carries server-controlled UDP Forward runtime limits.
type ForwardUDPConfig struct {
	AssociationIdleTimeout                time.Duration `json:"association_idle_timeout"`
	LinkWriteTimeout                      time.Duration `json:"link_write_timeout"`
	MaxDatagramSize                       int           `json:"max_datagram_size"`
	MaxAssociations                       int           `json:"max_associations"`
	MaxAssociationsPerClient              int           `json:"max_associations_per_client"`
	MaxAssociationsPerForward             int           `json:"max_associations_per_forward"`
	MaxAssociationsPerSourceIP            int           `json:"max_associations_per_source_ip"`
	MaxPendingAssociations                int           `json:"max_pending_associations"`
	MaxPendingAssociationsPerClient       int           `json:"max_pending_associations_per_client"`
	MaxPendingAssociationsPerForward      int           `json:"max_pending_associations_per_forward"`
	MaxNewAssociationsPerSecond           int           `json:"max_new_associations_per_second"`
	MaxNewAssociationsPerSecondPerClient  int           `json:"max_new_associations_per_second_per_client"`
	MaxNewAssociationsPerSecondPerForward int           `json:"max_new_associations_per_second_per_forward"`
	MaxQueuedDatagramsPerAssociation      int           `json:"max_queued_datagrams_per_association"`
	MaxQueuedBytesPerAssociation          int           `json:"max_queued_bytes_per_association"`
	MaxQueuedBytes                        int           `json:"max_queued_bytes"`
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
	RequestID       string        `json:"request_id"`
	LinkID          string        `json:"link_id,omitempty"`
	Name            string        `json:"name"`
	Type            ForwardType   `json:"type"`
	BindingID       string        `json:"binding_id"`
	Ticket          string        `json:"ticket,omitempty"`
	ExpiresAtUnixMS int64         `json:"expires_at_unix_ms,omitempty"`
	Error           *ForwardError `json:"error,omitempty"`
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
	Name       string            `json:"name"`
	Type       ForwardType       `json:"type"`
	BindingID  string            `json:"binding_id"`
	Generation uint64            `json:"generation"`
	UDP        *ForwardUDPConfig `json:"udp,omitempty"`
}
