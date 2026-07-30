// Package transport defines the transport boundary shared by client and server runtimes.
package transport

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
)

var (
	// ErrAuthentication indicates that the peer failed the configured Token proof.
	ErrAuthentication = errors.New("transport authentication failed")
	// ErrProtocol indicates malformed or invalid transport negotiation data.
	ErrProtocol = errors.New("invalid transport protocol")
	// ErrPermanent indicates a transport failure that cannot succeed without
	// changing credentials, trust settings, or protocol configuration.
	ErrPermanent = errors.New("permanent transport failure")
)

// Permanent marks an implementation-specific error as non-retryable while
// preserving it for errors.Is and errors.As inspection.
func Permanent(err error) error {
	if err == nil || IsPermanent(err) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrPermanent, err)
}

// IsPermanent reports whether reconnecting with unchanged configuration cannot
// resolve the transport failure.
func IsPermanent(err error) bool {
	return errors.Is(err, ErrPermanent) ||
		errors.Is(err, ErrAuthentication) ||
		errors.Is(err, ErrProtocol)
}

// Type identifies one implemented underlying transport.
type Type string

const (
	// TypeTCP uses independent token-protected TCP connections.
	TypeTCP Type = "tcp"
	// TypeQUIC uses one TLS-protected QUIC connection with multiple streams.
	TypeQUIC Type = "quic"
)

// ConnectionID is an opaque process-local identifier for a physical transport connection.
type ConnectionID string

// Generation identifies one process-local transport connection attempt.
type Generation uint64

// Stream is the reliable ordered byte-stream contract required by control and proxy layers.
//
// CloseWrite must end only the sending direction. Implementations that cannot preserve
// this behavior must not advertise support for TCP and HTTP proxy streams.
type Stream interface {
	net.Conn
	CloseWrite() error
}

// Client establishes transport sessions to one configured server.
type Client interface {
	Connect(context.Context) (ClientSession, error)
}

// ClientSession owns one control stream and creates data streams in the same generation.
type ClientSession interface {
	ControlStream() Stream
	OpenDataStream(context.Context) (Stream, error)
	ConnectionID() ConnectionID
	Generation() Generation
	Close() error
}

// Inbound is one authenticated stream accepted by a transport server.
type Inbound struct {
	Stream         Stream
	Role           protocol.Role
	Authentication authentication.Context
	ConnectionID   ConnectionID
	Generation     Generation
	RemoteAddress  string
}

// Server accepts authenticated inbound streams.
type Server interface {
	Accept(context.Context) (Inbound, error)
	RevokeAuthentication([]authentication.Context)
	Close() error
}
