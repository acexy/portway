package token

import (
	"context"
	"fmt"
	"net"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

// DialToken establishes a token-authenticated encrypted TCP connection.
func DialToken(ctx context.Context, address string, token string, role protocol.Role) (transport.Stream, error) {
	if token == "" {
		return nil, ErrAuthentication
	}
	rawConnection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial %q: %w", address, err)
	}
	stopContextClose := context.AfterFunc(ctx, func() {
		rawConnection.Close()
	})
	defer stopContextClose()
	secureConnection, err := clientTokenHandshake(ctx, rawConnection, token, role)
	if err != nil {
		rawConnection.Close()
		return nil, err
	}
	return secureConnection, nil
}

// AcceptToken authenticates a TCP connection when its declared role is allowed.
func AcceptToken(
	ctx context.Context,
	rawConnection net.Conn,
	credentials *authentication.Store,
	allowedRoles ...protocol.Role,
) (transport.Stream, protocol.Role, authentication.Context, error) {
	if credentials == nil {
		return nil, protocol.RoleUnknown, authentication.Context{}, ErrAuthentication
	}
	secureConnection, role, authenticationContext, err := serverTokenHandshakeContext(
		ctx, rawConnection, credentials, allowedRoles,
	)
	if err != nil {
		return nil, protocol.RoleUnknown, authentication.Context{}, err
	}
	return secureConnection, role, authenticationContext, nil
}
