package registry

import (
	"crypto/sha256"

	"github.com/acexy/portway/internal/protocol"
)

func (state *clientState) cacheSyncRequest(
	requestID string,
	revision uint64,
	fingerprint [sha256.Size]byte,
	result SyncResult,
) {
	if len(state.requestOrder) == maxCachedSyncRequests {
		oldest := state.requestOrder[0]
		state.requestOrder = state.requestOrder[1:]
		delete(state.requestCache, oldest)
	}
	state.requestOrder = append(state.requestOrder, requestID)
	state.requestCache[requestID] = cachedSyncRequest{
		revision: revision, fingerprint: fingerprint, result: result,
	}
}
func rejectedSyncResult(
	revision uint64,
	code ErrorCode,
	proxyName string,
	message string,
) SyncResult {
	return SyncResult{
		Revision: revision,
		Status:   SyncStatusRejected,
		Proxies:  []protocol.ProxyResult{},
		Error: &Error{
			Code:      code,
			Message:   message,
			ProxyName: proxyName,
			Retryable: code == ErrorSessionInactive,
		},
	}
}
