// Package tcp implements TCP Forward listener and target runtime behavior.
package tcp

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/acexy/portway/internal/link"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
)

// Listener owns one client-side TCP Forward listener.
type Listener struct {
	listener net.Listener
}

// Listen prepares one TCP Forward listener without starting its accept loop.
func Listen(ctx context.Context, address string) (*Listener, error) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	return &Listener{listener: listener}, nil
}

// Serve accepts visitors until the listener closes.
func (listener *Listener) Serve(handler func(net.Conn)) error {
	for {
		visitor, err := listener.listener.Accept()
		if err != nil {
			return err
		}
		handler(visitor)
	}
}

// Close releases the client-side listener.
func (listener *Listener) Close() error {
	return listener.listener.Close()
}

// Addr returns the bound client-side address.
func (listener *Listener) Addr() net.Addr {
	return listener.listener.Addr()
}

// Forward relays one visitor over an authenticated Forward stream.
func Forward(ctx context.Context, visitor net.Conn, stream net.Conn) error {
	_, err := proxytcp.Forward(ctx, visitor, stream)
	return err
}

// TargetHandlerFactory connects an authenticated stream to one server-side target.
func TargetHandlerFactory(
	address string,
	dialTimeout time.Duration,
	authorize func() bool,
) link.StreamHandlerFactory {
	return func(ctx context.Context) (link.StreamHandler, error) {
		if !authorize() {
			return nil, errors.New("Forward target is no longer allowed")
		}
		dialContext, cancel := context.WithTimeout(ctx, dialTimeout)
		defer cancel()
		target, err := (&net.Dialer{}).DialContext(dialContext, "tcp", address)
		if err != nil {
			return nil, err
		}
		return func(linkContext context.Context, _ string, stream net.Conn) error {
			defer target.Close()
			return Forward(linkContext, stream, target)
		}, nil
	}
}
