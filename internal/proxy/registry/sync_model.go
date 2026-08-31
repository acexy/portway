package registry

import "github.com/acexy/portway/internal/protocol"

// SyncStatus identifies the result of an atomic Registry transaction.
type SyncStatus string

const (
	// SyncStatusApplied indicates that the complete Proxy set is active.
	SyncStatusApplied SyncStatus = "applied"
	// SyncStatusRejected indicates that no part of the Proxy set was applied.
	SyncStatusRejected SyncStatus = "rejected"
)

// SyncRequest declares the complete Proxy set for one Session.
type SyncRequest struct {
	Revision uint64
	Proxies  []protocol.ProxyDeclaration
}

// SyncResult reports an atomic Registry transaction result.
type SyncResult struct {
	Revision uint64
	Status   SyncStatus
	Proxies  []protocol.ProxyResult
	Error    *Error
}
