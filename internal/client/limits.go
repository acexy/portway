package client

import "time"

const (
	initialReconnectDelay   = time.Second
	maximumReconnectDelay   = 30 * time.Second
	heartbeatInterval       = 5 * time.Second
	heartbeatTimeout        = 10 * time.Second
	sessionRecoveryWindow   = 90 * time.Second
	heartbeatCheckInterval  = time.Second
	controlHelloTimeout     = 10 * time.Second
	gracefulCloseTimeout    = 2 * time.Second
	reconnectJitterPercent  = 25
	localDialTimeout        = 5 * time.Second
	dataBindTimeout         = 5 * time.Second
)
