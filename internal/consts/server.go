package consts

import "time"

// ServerClientState represents the lifecycle state of a registered client.
type ServerClientState string

const (
	// ServerControlHelloTimeout limits the time allowed to complete control protocol negotiation.
	ServerControlHelloTimeout = 10 * time.Second
	// ServerControlHeartbeatTimeout is the maximum time an active client may remain without a valid Ping.
	ServerControlHeartbeatTimeout = 10 * time.Second
	// ServerClientRecoveryWindow controls how long a suspended client record remains recoverable.
	ServerClientRecoveryWindow = 60 * time.Second
	// ServerClientMonitorInterval controls how often the server checks client heartbeat state.
	ServerClientMonitorInterval = time.Second
	// ServerMaxConcurrentConnections limits connections being handled concurrently by the server.
	ServerMaxConcurrentConnections = 256
	// ServerMaxTCPProxiesPerClient limits TCP proxy listeners owned by one client.
	ServerMaxTCPProxiesPerClient = 128
	// ServerMaxTCPPendingLinks limits visitor connections waiting for data binding globally.
	ServerMaxTCPPendingLinks = 1024
	// ServerMaxTCPPendingLinksPerClient limits pending links owned by one client.
	ServerMaxTCPPendingLinksPerClient = 128
	// ServerMaxTCPPendingLinksPerProxy limits pending links owned by one TCP proxy.
	ServerMaxTCPPendingLinksPerProxy = 64
	// ServerMaxTCPActiveLinks limits bound TCP links globally.
	ServerMaxTCPActiveLinks = 4096
	// ServerMaxTCPActiveLinksPerClient limits active TCP links owned by one client.
	ServerMaxTCPActiveLinksPerClient = 512
	// ServerMaxTCPActiveLinksPerProxy limits active TCP links owned by one proxy.
	ServerMaxTCPActiveLinksPerProxy = 256
	// ServerClientStateActive identifies a client whose current control session is healthy.
	ServerClientStateActive ServerClientState = "active"
	// ServerClientStateSuspended identifies a client waiting for control session recovery.
	ServerClientStateSuspended ServerClientState = "suspended"
)
