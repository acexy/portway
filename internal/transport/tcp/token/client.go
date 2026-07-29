package token

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

var _ transport.Client = (*Client)(nil)
var _ transport.ClientSession = (*clientSession)(nil)

// Client adapts token-protected TCP connections to the common transport client contract.
type Client struct {
	address        string
	token          string
	nextGeneration atomic.Uint64
}

// NewClient creates a TCP token transport client.
func NewClient(address string, token string) *Client {
	return &Client{
		address: address,
		token:   token,
	}
}

// Connect establishes the control connection for a new transport generation.
func (client *Client) Connect(ctx context.Context) (transport.ClientSession, error) {
	generation := transport.Generation(client.nextGeneration.Add(1))
	connection, err := DialToken(ctx, client.address, client.token, protocol.RoleControl)
	if err != nil {
		return nil, err
	}
	sessionContext, cancel := context.WithCancel(context.Background())
	return &clientSession{
		client:       client,
		control:      connection,
		connectionID: transport.ConnectionID(fmt.Sprintf("tcp-client-%d", generation)),
		generation:   generation,
		context:      sessionContext,
		cancel:       cancel,
	}, nil
}

type clientSession struct {
	client       *Client
	control      transport.Stream
	connectionID transport.ConnectionID
	generation   transport.Generation
	context      context.Context
	cancel       context.CancelFunc
	mutex        sync.Mutex
	closed       bool
}

func (session *clientSession) ControlStream() transport.Stream {
	return session.control
}

func (session *clientSession) OpenDataStream(ctx context.Context) (transport.Stream, error) {
	session.mutex.Lock()
	closed := session.closed
	session.mutex.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	dialContext, cancel := context.WithCancel(ctx)
	stopSessionCancel := context.AfterFunc(session.context, cancel)
	defer func() {
		stopSessionCancel()
		cancel()
	}()
	return DialToken(
		dialContext,
		session.client.address,
		session.client.token,
		protocol.RoleData,
	)
}

func (session *clientSession) ConnectionID() transport.ConnectionID {
	return session.connectionID
}

func (session *clientSession) Generation() transport.Generation {
	return session.generation
}

func (session *clientSession) Close() error {
	session.mutex.Lock()
	if session.closed {
		session.mutex.Unlock()
		return nil
	}
	session.closed = true
	session.mutex.Unlock()
	session.cancel()
	return session.control.Close()
}
