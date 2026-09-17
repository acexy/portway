package protocol

// VNetState identifies one externally observable VNet lifecycle state.
type VNetState string

const (
	VNetStateDisabled             VNetState = "disabled"
	VNetStateEnabled              VNetState = "enabled"
	VNetStateInstallationRequired VNetState = "installation_required"
	VNetStateReady                VNetState = "ready"
	VNetStateActive               VNetState = "active"
	VNetStateRecovering           VNetState = "recovering"
	VNetStateFailed               VNetState = "failed"
)

// VNetAssignment contains the server-owned virtual address and channel policy.
type VNetAssignment struct {
	NetworkMode            string    `json:"network_mode"`
	CIDR                   string    `json:"cidr"`
	ClientIP               string    `json:"client_ip"`
	ServerIP               string    `json:"server_ip"`
	MTU                    uint16    `json:"mtu"`
	PacketChannels         uint8     `json:"packet_channels"`
	TransportGeneration    uint64    `json:"transport_generation"`
	PoolGeneration         uint64    `json:"pool_generation"`
	ConfigGeneration       uint64    `json:"config_generation"`
	State                  VNetState `json:"state"`
	PeerRegistrationTicket string    `json:"peer_registration_ticket,omitempty"`
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

// VNetPeerRole determines which endpoint initiates the QUIC handshake.
type VNetPeerRole string

const (
	VNetPeerRoleClient VNetPeerRole = "client"
	VNetPeerRoleServer VNetPeerRole = "server"
)

// VNetPeerState identifies the lifecycle of one client pair path.
type VNetPeerState string

const (
	VNetPeerStateReady  VNetPeerState = "ready"
	VNetPeerStateFailed VNetPeerState = "failed"
	VNetPeerStateClosed VNetPeerState = "closed"
)

// VNetPeerCandidate identifies one bounded UDP endpoint.
type VNetPeerCandidate struct {
	Address string `json:"address"`
	Type    string `json:"type"`
}

// VNetPeerPortRange is one inclusive direct-path inbound range.
type VNetPeerPortRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

// VNetPeerOffer authorizes one short-lived pair negotiation.
type VNetPeerOffer struct {
	PeerGeneration  uint64              `json:"peer_generation"`
	PeerClientID    string              `json:"peer_client_id"`
	PeerVirtualIP   string              `json:"peer_virtual_ip"`
	PeerFingerprint string              `json:"peer_fingerprint"`
	PairTicket      string              `json:"pair_ticket"`
	Role            VNetPeerRole        `json:"role"`
	Candidates      []VNetPeerCandidate `json:"candidates"`
	InboundTCP      []VNetPeerPortRange `json:"inbound_tcp"`
	InboundUDP      []VNetPeerPortRange `json:"inbound_udp"`
	ExpiresAtUnixMS int64               `json:"expires_at_unix_ms"`
}

// VNetPeerActivate publishes one mutually ready direct path.
type VNetPeerActivate struct {
	PeerGeneration uint64 `json:"peer_generation"`
	PeerClientID   string `json:"peer_client_id"`
}

// VNetPeerStatus reports one peer negotiation result.
type VNetPeerStatus struct {
	PeerGeneration uint64        `json:"peer_generation"`
	PeerClientID   string        `json:"peer_client_id"`
	State          VNetPeerState `json:"state"`
	Code           string        `json:"code,omitempty"`
}

// VNetPeerRevoke invalidates one direct path generation.
type VNetPeerRevoke struct {
	PeerGeneration uint64 `json:"peer_generation"`
	PeerClientID   string `json:"peer_client_id"`
	Reason         string `json:"reason"`
}

// VNetPeerFlowOpen registers the first packet metadata of one direct flow.
type VNetPeerFlowOpen struct {
	PeerGeneration  uint64 `json:"peer_generation"`
	PeerClientID    string `json:"peer_client_id"`
	Protocol        uint8  `json:"protocol"`
	SourceIP        string `json:"source_ip"`
	SourcePort      uint16 `json:"source_port"`
	DestinationIP   string `json:"destination_ip"`
	DestinationPort uint16 `json:"destination_port"`
	TCPFlags        uint8  `json:"tcp_flags,omitempty"`
}
