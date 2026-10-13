package client

import "time"

const (
	initialRegistrationReconnectDelay = time.Second
	maximumRegistrationReconnectDelay = 30 * time.Second
	initialRecoveryReconnectDelay     = 500 * time.Millisecond
	maximumRecoveryReconnectDelay     = 3 * time.Second
	controlSetupTimeout               = 20 * time.Second
	stableSessionPeriod               = time.Minute
	heartbeatInterval                 = 5 * time.Second
	heartbeatTimeout                  = 20 * time.Second
	sessionRecoveryWindow             = 90 * time.Second
	heartbeatCheckInterval            = time.Second
	controlHelloTimeout               = 10 * time.Second
	gracefulCloseTimeout              = 2 * time.Second
	reconnectJitterPercent            = 25
	localDialTimeout                  = 5 * time.Second
	dataBindTimeout                   = 5 * time.Second
)
