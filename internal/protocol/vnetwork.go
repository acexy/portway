package protocol

// VNetState identifies one externally observable VNet lifecycle state.
type VNetState string

const (
	VNetStateDisabled             VNetState = "disabled"
	VNetStateInstallationRequired VNetState = "installation_required"
	VNetStateActive               VNetState = "active"
	VNetStateFailed               VNetState = "failed"
)

// VNetAssignment contains the server-owned virtual address and channel policy.
type VNetAssignment struct {
	CIDR             string    `json:"cidr"`
	ClientIP         string    `json:"client_ip"`
	ServerIP         string    `json:"server_ip"`
	MTU              uint16    `json:"mtu"`
	PacketChannels   uint8     `json:"packet_channels"`
	PoolGeneration   uint64    `json:"pool_generation"`
	ConfigGeneration uint64    `json:"config_generation"`
	State            VNetState `json:"state"`
}

// VNetActivate identifies the assignment generation allowed to enter Active.
type VNetActivate struct {
	PoolGeneration   uint64 `json:"pool_generation"`
	ConfigGeneration uint64 `json:"config_generation"`
}

// VNetDeactivateReason identifies why VNet data flow was stopped.
type VNetDeactivateReason string

const (
	VNetDeactivateDisabled       VNetDeactivateReason = "disabled"
	VNetDeactivateNodeRemoved    VNetDeactivateReason = "node_removed"
	VNetDeactivatePolicyChanged  VNetDeactivateReason = "policy_changed"
	VNetDeactivateChannelFailure VNetDeactivateReason = "channel_failure"
)

// VNetDeactivate stops one active pool without closing the control session.
type VNetDeactivate struct {
	PoolGeneration   uint64               `json:"pool_generation"`
	ConfigGeneration uint64               `json:"config_generation"`
	Reason           VNetDeactivateReason `json:"reason"`
}

// OpenVNetChannel grants one short-lived ticket for an exact pool index.
type OpenVNetChannel struct {
	PoolGeneration  uint64 `json:"pool_generation"`
	ChannelIndex    uint8  `json:"channel_index"`
	ChannelCount    uint8  `json:"channel_count"`
	Ticket          string `json:"ticket"`
	ExpiresAtUnixMS int64  `json:"expires_at_unix_ms"`
}

// BindVNetChannel is the first encrypted frame on one VNet RoleData stream.
type BindVNetChannel struct {
	ClientID            string `json:"client_id"`
	SessionID           string `json:"session_id"`
	TransportGeneration uint64 `json:"transport_generation"`
	VirtualIP           string `json:"virtual_ip"`
	PoolGeneration      uint64 `json:"pool_generation"`
	ChannelIndex        uint8  `json:"channel_index"`
	ChannelCount        uint8  `json:"channel_count"`
	Ticket              string `json:"ticket"`
}

// VNetBindResult confirms one exact channel binding.
type VNetBindResult struct {
	PoolGeneration uint64     `json:"pool_generation"`
	ChannelIndex   uint8      `json:"channel_index"`
	Status         LinkStatus `json:"status"`
}

// VNetStatus reports readiness independently of Proxy and Forward state.
type VNetStatus struct {
	State            VNetState `json:"state"`
	PoolGeneration   uint64    `json:"pool_generation,omitempty"`
	ConfigGeneration uint64    `json:"config_generation"`
	Code             string    `json:"code,omitempty"`
}
