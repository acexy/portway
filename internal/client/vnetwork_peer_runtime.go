package client

import (
	"context"
	"sync"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/vnet"
)

// clientVNetPeerRuntime belongs to Service.Run, not a control session.
// Its socket remains bound during recovery while each endpoint is retired.
type clientVNetPeerRuntime struct {
	mutex       sync.Mutex
	bindAddress string
	socket      *vnet.PeerSocket
}

func (runtime *clientVNetPeerRuntime) newEndpoint(ctx context.Context, bindAddress, clientID, sessionID, virtualIP string, mtu uint16,
	status func(protocol.VNetPeerStatus) error, receive func([]byte) error) (*vnet.PeerEndpoint, error) {
	runtime.mutex.Lock()
	defer runtime.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runtime.socket != nil && (runtime.bindAddress != bindAddress || !runtime.socket.Healthy()) {
		_ = runtime.socket.Close()
		runtime.socket = nil
	}
	if runtime.socket == nil {
		socket, err := vnet.NewPeerSocket(bindAddress)
		if err != nil {
			return nil, err
		}
		runtime.socket = socket
		runtime.bindAddress = bindAddress
	}
	endpoint, err := runtime.socket.NewEndpoint(ctx, clientID, sessionID, virtualIP, mtu, status, receive)
	if err != nil && !runtime.socket.Healthy() {
		_ = runtime.socket.Close()
		runtime.socket = nil
	}
	return endpoint, err
}

func (runtime *clientVNetPeerRuntime) close() {
	runtime.mutex.Lock()
	defer runtime.mutex.Unlock()
	if runtime.socket != nil {
		_ = runtime.socket.Close()
		runtime.socket = nil
	}
	runtime.bindAddress = ""
}
