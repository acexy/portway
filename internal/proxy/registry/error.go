package registry

// ErrorCode identifies a stable Proxy Registry transaction failure.
type ErrorCode string

const (
	ErrorInvalidRequest          ErrorCode = "invalid_request"
	ErrorInvalidProxy            ErrorCode = "invalid_proxy"
	ErrorPortConflict            ErrorCode = "port_conflict"
	ErrorCapacityExceeded        ErrorCode = "capacity_exceeded"
	ErrorSessionInactive         ErrorCode = "session_inactive"
	ErrorPublicSchemeUnavailable ErrorCode = "public_scheme_unavailable"
	ErrorDomainConflict          ErrorCode = "domain_conflict"
	ErrorProxyTypeNotAllowed     ErrorCode = "proxy_type_not_allowed"
	ErrorRemotePortNotAllowed    ErrorCode = "remote_port_not_allowed"
	ErrorDomainNotAllowed        ErrorCode = "domain_not_allowed"
	ErrorPublicSchemeNotAllowed  ErrorCode = "public_scheme_not_allowed"
	ErrorClientLimitExceeded     ErrorCode = "client_limit_exceeded"
)

// Error describes a rejected Proxy Registry transaction.
type Error struct {
	Code      ErrorCode
	Message   string
	ProxyName string
	Retryable bool
}
