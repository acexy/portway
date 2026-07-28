// Package consts contains shared runtime constants for Portway components.
package consts

import "time"

const (
	// ClientInitialReconnectDelay is the first delay before retrying a failed control connection.
	ClientInitialReconnectDelay = time.Second
	// ClientMaximumReconnectDelay limits exponential backoff between control connection attempts.
	ClientMaximumReconnectDelay = 30 * time.Second
	// ClientHeartbeatInterval controls how often the client sends a Ping on an active control session.
	ClientHeartbeatInterval = 5 * time.Second
	// ClientHeartbeatTimeout is the maximum time the client accepts without receiving a valid Pong.
	ClientHeartbeatTimeout = 10 * time.Second
	// ClientSessionRecoveryWindow limits how long the client tries to resume a disconnected session.
	ClientSessionRecoveryWindow = 90 * time.Second
	// ClientHeartbeatCheckInterval controls how often the client checks whether Pong responses timed out.
	ClientHeartbeatCheckInterval = time.Second
	// ClientControlHelloTimeout limits the initial control protocol negotiation.
	ClientControlHelloTimeout = 10 * time.Second
	// ClientGracefulCloseTimeout limits how long the client waits for a CloseAck during shutdown.
	ClientGracefulCloseTimeout = 2 * time.Second
	// ClientReconnectJitterPercent is the maximum percentage added to or removed from a retry delay.
	ClientReconnectJitterPercent = 25
)
