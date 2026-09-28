package registry

import systemlimits "github.com/acexy/portway/internal/limits"

const (
	maxProxiesPerClient   = systemlimits.HardMaxBindingsPerClient
	maxCachedSyncRequests = 16
)
