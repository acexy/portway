package consts

import "time"

const (
	// TCPPendingLinkTimeout limits how long a visitor waits for a RoleData connection.
	TCPPendingLinkTimeout = 10 * time.Second
	// TCPDataBindTimeout limits RoleData BindLink negotiation.
	TCPDataBindTimeout = 5 * time.Second
	// TCPLocalDialTimeout limits client connections to local TCP services.
	TCPLocalDialTimeout = 5 * time.Second
	// TCPStreamCloseGracePeriod limits how long the remaining copy direction may drain.
	TCPStreamCloseGracePeriod = 5 * time.Second
)
