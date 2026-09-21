package vnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/acexy/portway/internal/protocol"
	quicgo "github.com/quic-go/quic-go"
)

// PeerSocket owns the process-scoped UDP binding. Session endpoints borrow its
// transport sequentially without rebinding the port or inheriting authority.
type PeerSocket struct {
	mutex      sync.Mutex
	connection *net.UDPConn
	transport  *quicgo.Transport
	endpoint   *PeerEndpoint
	closed     bool
	broken     atomic.Bool
	closeOnce  sync.Once
}

// NewPeerSocket reserves the UDP port before any session starts probing.
func NewPeerSocket(bindAddress string) (*PeerSocket, error) {
	address, err := net.ResolveUDPAddr("udp4", bindAddress)
	if err != nil {
		return nil, fmt.Errorf("resolve VNet P2P UDP address: %w", err)
	}
	connection, err := net.ListenUDP("udp4", address)
	if err != nil {
		return nil, fmt.Errorf("bind VNet P2P UDP address %q: %w", bindAddress, err)
	}
	return &PeerSocket{connection: connection, transport: &quicgo.Transport{Conn: connection}}, nil
}

// Healthy reports whether a later assignment can reuse this binding.
func (socket *PeerSocket) Healthy() bool {
	socket.mutex.Lock()
	defer socket.mutex.Unlock()
	return !socket.closed && !socket.broken.Load()
}

// NewEndpoint attaches fresh session authority to an otherwise unchanged socket.
// The previous endpoint must have completed Close before its successor starts.
func (socket *PeerSocket) NewEndpoint(parent context.Context, clientID, sessionID, virtualIP string, mtu uint16,
	status func(protocol.VNetPeerStatus) error, receive func([]byte) error) (*PeerEndpoint, error) {
	socket.mutex.Lock()
	defer socket.mutex.Unlock()
	if socket.closed || socket.broken.Load() {
		return nil, net.ErrClosed
	}
	if socket.endpoint != nil {
		return nil, errors.New("VNet peer socket already has a session")
	}
	endpoint, err := newPeerEndpoint(parent, socket, clientID, sessionID, virtualIP, mtu, status, receive)
	if err != nil {
		return nil, err
	}
	socket.endpoint = endpoint
	endpoint.waitGroup.Go(endpoint.acceptConnections)
	endpoint.waitGroup.Go(endpoint.readSignals)
	return endpoint, nil
}

func (socket *PeerSocket) release(endpoint *PeerEndpoint) {
	socket.mutex.Lock()
	if socket.endpoint == endpoint {
		socket.endpoint = nil
	}
	socket.mutex.Unlock()
}

// Close quiesces any active session before releasing the shared transport and UDP port.
func (socket *PeerSocket) Close() error {
	socket.closeOnce.Do(func() {
		socket.mutex.Lock()
		socket.closed = true
		endpoint := socket.endpoint
		socket.mutex.Unlock()
		if endpoint != nil {
			endpoint.closeSession()
		}
		_ = socket.transport.Close()
		_ = socket.connection.Close()
	})
	return nil
}
