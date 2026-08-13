package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/acexy/golang-toolkit/util/coll"
	quicgo "github.com/quic-go/quic-go"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/security/ipfilter"
	"github.com/acexy/portway/internal/transport"
)

var _ transport.Server = (*Server)(nil)

// ServerConfig contains the QUIC server transport settings.
type ServerConfig struct {
	Address     string
	CertFile    string
	KeyFile     string
	Credentials *authentication.Store
}

type acceptResult struct {
	inbound transport.Inbound
	err     error
}

// Server accepts Token-authenticated QUIC connections and their logical streams.
type Server struct {
	listener       *quicgo.Listener
	credentials    *authentication.Store
	context        context.Context
	cancel         context.CancelFunc
	connectionSlot chan struct{}
	sourceLimiter  *authentication.SourceFailureLimiter
	results        chan acceptResult
	nextGeneration atomic.Uint64
	mutex          sync.Mutex
	connections    map[*quicgo.Conn]authentication.Context
	sourceFilter   *ipfilter.Filter
	closeOnce      sync.Once
	closeError     error
	waitGroup      sync.WaitGroup
}

// NewServer creates and starts a QUIC transport server.
func NewServer(
	ctx context.Context,
	configuration ServerConfig,
	maxConcurrentConnections int,
	sourceFilters ...*ipfilter.Filter,
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
	credentials := configuration.Credentials
	if credentials == nil {
		cancel()
		listener.Close()
		return nil, transport.ErrAuthentication
	}
	resultCapacity := max(maxConcurrentConnections*2, 1)
	var sourceFilter *ipfilter.Filter
	if len(sourceFilters) > 0 {
		sourceFilter = sourceFilters[0]
	}
	server := &Server{
		listener:       listener,
		credentials:    credentials,
		context:        serverContext,
		cancel:         cancel,
		connectionSlot: make(chan struct{}, maxConcurrentConnections),
		sourceLimiter:  authentication.NewSourceFailureLimiter(),
		results:        make(chan acceptResult, resultCapacity),
		connections:    make(map[*quicgo.Conn]authentication.Context),
		sourceFilter:   sourceFilter,
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
		sourceAddress, parseError := ipfilter.ParseRemoteAddress(connection.RemoteAddr())
		if parseError != nil || !server.sourceLimiter.Allow(sourceAddress) {
			connection.CloseWithError(applicationErrorAuth, "authentication rate limited")
			continue
		}
		var releaseSource func()
		if server.sourceFilter.Enabled() {
			var allowed bool
			releaseSource, allowed = server.sourceFilter.RegisterFor(
				sourceAddress,
				"transport_quic",
				func() {
					connection.CloseWithError(
						applicationErrorShutdown,
						"source address denied",
					)
				},
			)
			if !allowed {
				connection.CloseWithError(
					applicationErrorShutdown,
					"source address denied",
				)
				continue
			}
		}
		select {
		case server.connectionSlot <- struct{}{}:
		default:
			if releaseSource != nil {
				releaseSource()
			}
			connection.CloseWithError(
				applicationErrorShutdown,
				"QUIC connection capacity reached",
			)
			continue
		}
		server.addConnection(connection)
		server.waitGroup.Add(1)
		go server.handleConnection(connection, sourceAddress, releaseSource)
	}
}

func (server *Server) handleConnection(
	connection *quicgo.Conn,
	sourceAddress netip.Addr,
	releaseSource func(),
) {
	defer server.waitGroup.Done()
	defer func() {
		if releaseSource != nil {
			releaseSource()
		}
		server.removeConnection(connection)
		<-server.connectionSlot
	}()

	firstStreamContext, cancelFirstStream := context.WithTimeout(
		server.context,
		authenticationTimeout,
	)
	controlStream, err := connection.AcceptStream(firstStreamContext)
	cancelFirstStream()
	if err != nil {
		server.sourceLimiter.RecordFailure(sourceAddress)
		connection.CloseWithError(applicationErrorAuth, "authentication stream timeout")
		return
	}
	streamContext, cancelStreams := context.WithCancel(server.context)
	var streamWaitGroup sync.WaitGroup
	dataStreams := make(chan *quicgo.Stream)
	streamErrors := make(chan error, 1)
	var authenticated atomic.Bool
	streamWaitGroup.Add(1)
	go func() {
		defer streamWaitGroup.Done()
		for {
			dataStream, acceptError := connection.AcceptStream(streamContext)
			if acceptError != nil {
				select {
				case streamErrors <- acceptError:
				default:
				}
				return
			}
			if !authenticated.Load() {
				dataStream.CancelRead(streamErrorClosed)
				dataStream.CancelWrite(streamErrorClosed)
				continue
			}
			select {
			case dataStreams <- dataStream:
			case <-streamContext.Done():
				dataStream.CancelRead(streamErrorClosed)
				dataStream.CancelWrite(streamErrorClosed)
				return
			}
		}
	}()
	defer func() {
		cancelStreams()
		streamWaitGroup.Wait()
	}()
	authenticationContext, err := authenticateServer(
		server.context,
		controlStream,
		server.credentials,
	)
	if err != nil {
		server.sourceLimiter.RecordFailure(sourceAddress)
		errorCode := applicationErrorProtocol
		if errors.Is(err, transport.ErrAuthentication) {
			errorCode = applicationErrorAuth
		}
		connection.CloseWithError(errorCode, "QUIC authentication failed")
		return
	}
	server.sourceLimiter.RecordSuccess(sourceAddress)
	authenticated.Store(true)
	server.setConnectionAuthentication(connection, authenticationContext)
	if !server.credentials.IsCurrent(authenticationContext) {
		connection.CloseWithError(applicationErrorAuth, "authentication revoked")
		return
	}

	generation := transport.Generation(server.nextGeneration.Add(1))
	connectionID := transport.ConnectionID(fmt.Sprintf("quic-server-%d", generation))
	remoteAddress := connection.RemoteAddr().String()
	if !server.publish(acceptResult{inbound: transport.Inbound{
		Stream:         newStream(controlStream, connection, true),
		Role:           protocol.RoleControl,
		Authentication: authenticationContext,
		ConnectionID:   connectionID,
		Generation:     generation,
		RemoteAddress:  remoteAddress,
	}}) {
		connection.CloseWithError(applicationErrorShutdown, "server stopped")
		return
	}

	for {
		var dataStream *quicgo.Stream
		select {
		case dataStream = <-dataStreams:
		case <-streamErrors:
			return
		case <-server.context.Done():
			return
		}
		if !server.credentials.IsCurrent(authenticationContext) {
			dataStream.CancelRead(streamErrorClosed)
			dataStream.CancelWrite(streamErrorClosed)
			connection.CloseWithError(applicationErrorAuth, "authentication revoked")
			return
		}
		if !server.publish(acceptResult{inbound: transport.Inbound{
			Stream:         newStream(dataStream, connection, false),
			Role:           protocol.RoleData,
			Authentication: authenticationContext,
			ConnectionID:   connectionID,
			Generation:     generation,
			RemoteAddress:  remoteAddress,
		}}) {
			dataStream.CancelRead(streamErrorClosed)
			dataStream.CancelWrite(streamErrorClosed)
			return
		}
	}
}

// RevokeAuthentication closes QUIC connections authenticated by revoked records.
func (server *Server) RevokeAuthentication(contexts []authentication.Context) {
	type revokedRecord struct {
		credentialID [32]byte
		generation   uint64
	}
	revoked := make(map[revokedRecord]struct{}, len(contexts))
	for _, context := range contexts {
		revoked[revokedRecord{
			credentialID: context.CredentialID,
			generation:   context.Generation,
		}] = struct{}{}
	}
	server.mutex.Lock()
	connections := make([]*quicgo.Conn, 0)
	for connection, context := range server.connections {
		if _, exists := revoked[revokedRecord{
			credentialID: context.CredentialID,
			generation:   context.Generation,
		}]; exists {
			connections = append(connections, connection)
		}
	}
	server.mutex.Unlock()
	for _, connection := range connections {
		connection.CloseWithError(applicationErrorAuth, "authentication revoked")
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
		connections := coll.MapKeys(server.connections)
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
	server.connections[connection] = authentication.Context{}
	server.mutex.Unlock()
}

func (server *Server) setConnectionAuthentication(
	connection *quicgo.Conn,
	context authentication.Context,
) {
	server.mutex.Lock()
	if _, exists := server.connections[connection]; exists {
		server.connections[connection] = context
	}
	server.mutex.Unlock()
}

func (server *Server) removeConnection(connection *quicgo.Conn) {
	server.mutex.Lock()
	delete(server.connections, connection)
	server.mutex.Unlock()
}
