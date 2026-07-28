// Package transport defines secure transport and logical connection boundaries.
package transport

import (
	"context"
	"net"

	"github.com/acexy/portway/internal/protocol"
)

// Endpoint represents a transport connection endpoint.
type Endpoint struct {
	Network string
	Address string
}

// Dialer establishes a secure connection for the specified role.
//
// Implementations establish the selected secure channel but do not handle
// proxy registration or authorization.
type Dialer interface {
	Dial(ctx context.Context, endpoint Endpoint, role protocol.Role) (net.Conn, error)
}

// Acceptor accepts secure connections after the transport handshake completes.
//
// Implementations must allow a context to cancel a blocked Accept call.
type Acceptor interface {
	Accept(ctx context.Context) (net.Conn, protocol.Role, error)
	Addr() net.Addr
	Close() error
}

// HalfCloser describes a connection that supports TCP half-close operations.
type HalfCloser interface {
	CloseRead() error
	CloseWrite() error
}
