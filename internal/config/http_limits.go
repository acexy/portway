package config

import "time"

const (
	httpDefaultReadHeaderTimeout               = 10 * time.Second
	httpDefaultGracefulShutdownTimeout         = 30 * time.Second
	httpDefaultMaxHeaderBytes                  = 64 * 1024
	httpDefaultMaxConcurrentRequests           = 4096
	httpDefaultMaxConcurrentRequestsPerClient  = 512
	httpDefaultMaxConcurrentRequestsPerDomain  = 256
	httpDefaultMaxIdleConnections              = 1024
	httpDefaultMaxIdleConnectionsPerDomain     = 32
	httpDefaultMaxUpgradeConnections           = 1024
	httpDefaultMaxUpgradeConnectionsPerClient  = 128
	httpDefaultMaxUpgradeConnectionsPerDomain  = 64
	httpDefaultMaxConcurrentHTTP2Streams       = 128

	httpHardMaxReadHeaderTimeout               = 60 * time.Second
	httpHardMaxGracefulShutdownTimeout         = 2 * time.Minute
	httpHardMaxBusinessTimeout                 = 10 * time.Minute
	httpHardMaxHeaderBytes                     = 1024 * 1024
	httpHardMaxConcurrentRequests              = 16384
	httpHardMaxConcurrentRequestsPerClient     = 2048
	httpHardMaxConcurrentRequestsPerDomain     = 1024
	httpHardMaxIdleConnections                 = 4096
	httpHardMaxIdleConnectionsPerDomain        = 128
	httpHardMaxUpgradeConnections              = 4096
	httpHardMaxUpgradeConnectionsPerClient     = 512
	httpHardMaxUpgradeConnectionsPerDomain     = 256
	httpHardMaxConcurrentHTTP2Streams          = 256
)
