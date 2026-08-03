package token

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/security/ipfilter"
	"github.com/acexy/portway/internal/transport"
)

var _ transport.Server = (*Server)(nil)

type acceptResult struct {
	inbound transport.Inbound
	err     error
}

// RevokeAuthentication is a no-op for TCP because every physical connection
// is independently authenticated and application owners close its Stream.
func (server *Server) RevokeAuthentication(_ []authentication.Context) {}

// Server accepts and authenticates token-protected TCP connections.
type Server struct {
	listener       net.Listener
	credentials    *authentication.Store
	context        context.Context
	cancel         context.CancelFunc
	connectionSlot chan struct{}
	results        chan acceptResult
	nextGeneration atomic.Uint64
	closeOnce      sync.Once
	waitGroup      sync.WaitGroup
}

// NewServer creates and starts a TCP token transport server.
func NewServer(
	ctx context.Context,
	address string,
	credentials *authentication.Store,
	maxConcurrentConnections int,
	sourceFilters ...*ipfilter.Filter,
) (*Server, error) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", address, err)
	}
	if len(sourceFilters) > 0 {
		listener = ipfilter.WrapListenerFor(listener, sourceFilters[0], "transport_tcp")
	}
	if credentials == nil {
		listener.Close()
		return nil, transport.ErrAuthentication
	}
	serverContext, cancel := context.WithCancel(ctx)
	server := &Server{
		listener:       listener,
		credentials:    credentials,
		context:        serverContext,
		cancel:         cancel,
		connectionSlot: make(chan struct{}, maxConcurrentConnections),
		results:        make(chan acceptResult, maxConcurrentConnections),
	}
	server.waitGroup.Add(1)
	go server.acceptLoop()
	return server, nil
}

func (server *Server) acceptLoop() {
	defer server.waitGroup.Done()
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			if server.context.Err() == nil && !errors.Is(err, net.ErrClosed) {
				server.publish(acceptResult{err: fmt.Errorf("accept client connection: %w", err)})
			}
			return
		}
		select {
		case server.connectionSlot <- struct{}{}:
		default:
			connection.Close()
			continue
		}
		server.waitGroup.Add(1)
		go server.authenticate(connection)
	}
}

func (server *Server) authenticate(rawConnection net.Conn) {
	defer server.waitGroup.Done()
	defer func() {
		<-server.connectionSlot
	}()

	remoteAddress := rawConnection.RemoteAddr().String()
	stream, role, authenticationContext, err := AcceptToken(
		server.context,
		rawConnection,
		server.credentials,
		protocol.RoleControl,
		protocol.RoleData,
	)
	if err != nil {
		rawConnection.Close()
		return
	}
	generation := transport.Generation(server.nextGeneration.Add(1))
	if !server.publish(acceptResult{inbound: transport.Inbound{
		Stream:         stream,
		Role:           role,
		Authentication: authenticationContext,
		ConnectionID:   transport.ConnectionID(fmt.Sprintf("tcp-server-%d", generation)),
		Generation:     generation,
		RemoteAddress:  remoteAddress,
	}}) {
		stream.Close()
	}
}

func (server *Server) publish(result acceptResult) bool {
	select {
	case server.results <- result:
		return true
	case <-server.context.Done():
		return false
	}
}

// Accept returns the next authenticated TCP stream.
func (server *Server) Accept(ctx context.Context) (transport.Inbound, error) {
	select {
	case result := <-server.results:
		return result.inbound, result.err
	case <-ctx.Done():
		return transport.Inbound{}, ctx.Err()
	case <-server.context.Done():
		return transport.Inbound{}, net.ErrClosed
	}
}

// Close stops accepting connections and waits for adapter-owned work to finish.
func (server *Server) Close() error {
	var closeError error
	server.closeOnce.Do(func() {
		server.cancel()
		closeError = server.listener.Close()
		server.waitGroup.Wait()
	})
	return closeError
}
