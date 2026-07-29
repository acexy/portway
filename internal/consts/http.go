package consts

import "time"

const (
	HTTPDefaultReadHeaderTimeout               = 10 * time.Second
	HTTPDefaultGracefulShutdownTimeout         = 30 * time.Second
	HTTPDefaultMaxHeaderBytes                  = 64 * 1024
	HTTPDefaultMaxConcurrentRequests           = 4096
	HTTPDefaultMaxConcurrentRequestsPerClient  = 512
	HTTPDefaultMaxConcurrentRequestsPerDomain  = 256
	HTTPDefaultMaxIdleConnections              = 1024
	HTTPDefaultMaxIdleConnectionsPerDomain     = 32
	HTTPDefaultMaxUpgradeConnections           = 1024
	HTTPDefaultMaxUpgradeConnectionsPerClient  = 128
	HTTPDefaultMaxUpgradeConnectionsPerDomain  = 64
	HTTPDefaultMaxConcurrentHTTP2Streams       = 128

	HTTPHardMaxReadHeaderTimeout               = 60 * time.Second
	HTTPHardMaxGracefulShutdownTimeout         = 2 * time.Minute
	HTTPHardMaxBusinessTimeout                 = 10 * time.Minute
	HTTPHardMaxHeaderBytes                     = 1024 * 1024
	HTTPHardMaxConcurrentRequests              = 16384
	HTTPHardMaxConcurrentRequestsPerClient     = 2048
	HTTPHardMaxConcurrentRequestsPerDomain     = 1024
	HTTPHardMaxIdleConnections                 = 4096
	HTTPHardMaxIdleConnectionsPerDomain        = 128
	HTTPHardMaxUpgradeConnections              = 4096
	HTTPHardMaxUpgradeConnectionsPerClient     = 512
	HTTPHardMaxUpgradeConnectionsPerDomain     = 256
	HTTPHardMaxConcurrentHTTP2Streams           = 256
)
