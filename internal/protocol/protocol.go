// Package protocol defines the stable foundation types of the Portway wire protocol.
package protocol

const (
	// Magic identifies Portway protocol frames.
	Magic = "PTWY"

	// MajorVersion is the current protocol major version.
	MajorVersion uint8 = 1
)

// Role identifies the protocol role assigned to a connection.
type Role uint8

const (
	// RoleUnknown indicates that the connection role has not been determined.
	RoleUnknown Role = iota
	// RoleControl identifies a control connection.
	RoleControl
	// RoleData identifies a data connection.
	RoleData
)

// Valid reports whether the role can be negotiated on a connection.
func (role Role) Valid() bool {
	return role == RoleControl || role == RoleData
}

const (
	// ALPNControlV1 is the ALPN identifier for version 1 control connections.
	ALPNControlV1 = "portway-control/1"
	// ALPNDataV1 is the ALPN identifier for version 1 data connections.
	ALPNDataV1 = "portway-data/1"
)
