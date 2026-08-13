package server

import "time"

const (
	controlHelloTimeout         = 10 * time.Second
	managedRolloutTimeout       = 10 * time.Second
	controlHeartbeatTimeout     = 10 * time.Second
	clientRecoveryWindow        = 60 * time.Second
	clientMonitorInterval       = time.Second
	maxConcurrentConnections    = 256
	maxClientSessions           = 256
	dataBindTimeout             = 5 * time.Second
	operationsReadHeaderTimeout = 5 * time.Second
	operationsShutdownTimeout   = 5 * time.Second
	operationsMaxHeaderBytes    = 8 * 1024
)
