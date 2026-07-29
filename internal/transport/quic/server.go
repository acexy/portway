package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	quicgo "github.com/quic-go/quic-go"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

var _ transport.Server = (*Server)(nil)

// ServerConfig contains the QUIC server transport settings.
type ServerConfig struct {
	Address  string
	CertFile string
	KeyFile  string
	Token    string
}

type acceptResult struct {
	inbound transport.Inbound
	err     error
}

// Server accepts Token-authenticated QUIC connections and their logical streams.
type Server struct {
	listener       *quicgo.Listener
	token          string
	context        context.Context
	cancel         context.CancelFunc
	connectionSlot chan struct{}
	results        chan acceptResult
	nextGeneration atomic.Uint64
	mutex          sync.Mutex
	connections    map[*quicgo.Conn]struct{}
	closeOnce      sync.Once
	closeError     error
	waitGroup      sync.WaitGroup
}

// NewServer creates and starts a QUIC transport server.
func NewServer(
	ctx context.Context,
	configuration ServerConfig,
	maxConcurrentConnections int,
) (*Server, error) {
	certificate, err := tls.LoadX509KeyPair(
		configuration.CertFile,
		configuration.KeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("load QUIC server certificate: %w", err)
	}
	listener, err := quicgo.ListenAddr(
		configuration.Address,
		&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{alpn},
		},
		defaultQUICConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("listen for QUIC connections on %q: %w", configuration.Address, err)
	}
	serverContext, cancel := context.WithCancel(ctx)
	resultCapacity := max(maxConcurrentConnections*2, 1)
	server := &Server{
		listener:       listener,
		token:          configuration.Token,
		context:        serverContext,
		cancel:         cancel,
		connectionSlot: make(chan struct{}, maxConcurrentConnections),
		results:        make(chan acceptResult, resultCapacity),
		connections:    make(map[*quicgo.Conn]struct{}),
	}
	server.waitGroup.Add(1)
	go server.acceptConnections()
	return server, nil
}

func (server *Server) acceptConnections() {
	defer server.waitGroup.Done()
	for {
		connection, err := server.listener.Accept(server.context)
		if err != nil {
			if server.context.Err() == nil && !errors.Is(err, quicgo.ErrServerClosed) {
				server.publish(acceptResult{
					err: fmt.Errorf("accept QUIC connection: %w", err),
				})
			}
			return
		}
		select {
		case server.connectionSlot <- struct{}{}:
		default:
			connection.CloseWithError(
				applicationErrorShutdown,
				"QUIC connection capacity reached",
			)
			continue
		}
		server.addConnection(connection)
		server.waitGroup.Add(1)
		go server.handleConnection(connection)
	}
}

func (server *Server) handleConnection(connection *quicgo.Conn) {
	defer server.waitGroup.Done()
	defer func() {
		server.removeConnection(connection)
		<-server.connectionSlot
	}()

	controlStream, err := connection.AcceptStream(server.context)
	if err != nil {
		return
	}
	if err := authenticateServer(server.context, controlStream, server.token); err != nil {
		errorCode := applicationErrorProtocol
		if errors.Is(err, transport.ErrAuthentication) {
			errorCode = applicationErrorAuth
		}
		connection.CloseWithError(errorCode, "QUIC authentication failed")
		return
	}

	generation := transport.Generation(server.nextGeneration.Add(1))
	connectionID := transport.ConnectionID(fmt.Sprintf("quic-server-%d", generation))
	remoteAddress := connection.RemoteAddr().String()
	if !server.publish(acceptResult{inbound: transport.Inbound{
		Stream:        newStream(controlStream, connection, true),
		Role:          protocol.RoleControl,
		ConnectionID:  connectionID,
		Generation:    generation,
		RemoteAddress: remoteAddress,
	}}) {
		connection.CloseWithError(applicationErrorShutdown, "server stopped")
		return
	}

	for {
		dataStream, err := connection.AcceptStream(server.context)
		if err != nil {
			return
		}
		if !server.publish(acceptResult{inbound: transport.Inbound{
			Stream:        newStream(dataStream, connection, false),
			Role:          protocol.RoleData,
			ConnectionID:  connectionID,
			Generation:    generation,
			RemoteAddress: remoteAddress,
		}}) {
			dataStream.CancelRead(streamErrorClosed)
			dataStream.CancelWrite(streamErrorClosed)
			return
		}
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

// Accept returns the next authenticated QUIC control or data stream.
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

// Close stops accepting connections and closes every adapter-owned connection.
func (server *Server) Close() error {
	server.closeOnce.Do(func() {
		server.cancel()
		server.closeError = server.listener.Close()
		server.mutex.Lock()
		connections := make([]*quicgo.Conn, 0, len(server.connections))
		for connection := range server.connections {
			connections = append(connections, connection)
		}
		server.mutex.Unlock()
		for _, connection := range connections {
			connection.CloseWithError(applicationErrorShutdown, "server stopped")
		}
		server.waitGroup.Wait()
	})
	return server.closeError
}

func (server *Server) addConnection(connection *quicgo.Conn) {
	server.mutex.Lock()
	server.connections[connection] = struct{}{}
	server.mutex.Unlock()
}

func (server *Server) removeConnection(connection *quicgo.Conn) {
	server.mutex.Lock()
	delete(server.connections, connection)
	server.mutex.Unlock()
}
