package registry

// SyncCoordinated prepares resources before invoking a companion's publication
// barrier. The companion must call publish synchronously, at most once, and
// must not perform I/O or cleanup. Resource retirement follows both publications.
func (manager *Registry) SyncCoordinated(clientID, sessionID, requestID string, request SyncRequest, coordinate func(func() bool) bool) SyncResult {
	return manager.sync(clientID, sessionID, requestID, request, true, coordinate)
}

func coordinateCachedSync(result SyncResult, coordinate func(func() bool) bool) SyncResult {
	if coordinate != nil && !coordinate(func() bool { return true }) {
		return rejectedSyncResult(result.Revision, ErrorSessionInactive, "", "companion generation changed during registration")
	}
	return result
}

func (manager *Registry) commitSync(preparation syncCommitPreparation, coordinate func(func() bool) bool) SyncResult {
	var result SyncResult
	var retire func()
	manager.registrationMutex.Lock()
	publish := func() bool {
		result, retire = manager.publishSync(preparation)
		return result.Status == SyncStatusApplied
	}
	if coordinate == nil {
		publish()
	} else if !coordinate(publish) && result.Status != SyncStatusRejected {
		result = rejectedSyncResult(preparation.request.Revision, ErrorSessionInactive, "", "companion generation changed during registration")
	}
	if retire != nil {
		// Start ownership tasks before removal can close and join them.
		for _, endpoint := range preparation.newEndpoints {
			endpoint.Start()
		}
		for _, endpoint := range preparation.newUDPEndpoints {
			endpoint.Start()
		}
	}
	manager.registrationMutex.Unlock()
	if retire != nil {
		retire()
	} else {
		rollbackSyncPreparation(preparation.newEndpoints, preparation.newUDPEndpoints,
			preparation.nextUDPProxies, preparation.existingUDPProxies,
			preparation.nextHTTPProxies, preparation.existingHTTPProxies)
	}
	return result
}
