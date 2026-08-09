package registry

import (
	"crypto/sha256"

	"github.com/acexy/portway/internal/protocol"
)

func (state *clientState) cacheSyncRequest(
	requestID string,
	revision uint64,
	fingerprint [sha256.Size]byte,
	result protocol.SyncResult,
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
	code protocol.ProxyErrorCode,
	proxyName string,
	message string,
) protocol.SyncResult {
	return protocol.SyncResult{
		Revision: revision,
		Status:   protocol.ProxySyncStatusRejected,
		Proxies:  []protocol.ProxyResult{},
		Error: &protocol.ProxyError{
			Code:      code,
			Message:   message,
			ProxyName: proxyName,
			Retryable: code == protocol.ProxyErrorSessionInactive,
		},
	}
}
