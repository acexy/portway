// Package server provides the Portway server runtime.
package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
	proxyregistry "github.com/acexy/portway/internal/proxy/registry"
	"github.com/acexy/portway/internal/security/ipfilter"
	"github.com/acexy/portway/internal/session"
	"github.com/acexy/portway/internal/transport"
	transportfactory "github.com/acexy/portway/internal/transport/factory"
)

var errProxyRegistrationRejected = errors.New("proxy registration rejected")

// Service manages the server process lifecycle.
//
// It owns the client listener, control sessions, proxy registration, and
// session-scoped TCP proxy resources.
type Service struct {
	logger         *logging.Logger
	configuration  config.ServerConfig
	clientRegistry *session.Registry
	proxyRegistry  *proxyregistry.Registry
	linkBroker      *link.Broker
	transportServer transport.Server
}

// NewService creates a server service.
func NewService(logger *logging.Logger, configuration config.ServerConfig) *Service {
	return &Service{
		logger:         logger,
		configuration:  configuration,
		clientRegistry: session.NewRegistry(),
	}
}

// Run runs the server until the parent context is canceled.
func (s *Service) Run(ctx context.Context) error {
	s.logger.InfoWithField(
		"server started",
		"listen_address",
		s.configuration.Transport.ListenAddress,
	)
	defer s.logger.Info("server stopped")

	sourceFilter, err := ipfilter.New(
		ctx,
		s.logger,
		s.configuration.Security.IPDenyFile,
	)
	if err != nil {
		return err
	}
	defer sourceFilter.Close()

	transportServer, err := transportfactory.NewServer(
		ctx,
		s.configuration,
		maxConcurrentConnections,
		sourceFilter,
	)
	if err != nil {
		return err
	}
	s.transportServer = transportServer
	defer transportServer.Close()

	var sessions sync.WaitGroup
	defer sessions.Wait()
	sessionContext, cancelSessions := context.WithCancel(ctx)
	s.linkBroker = link.NewBroker(sessionContext)
	defer s.linkBroker.Close()
	s.proxyRegistry = proxyregistry.NewConfigured(
		sessionContext,
		s.logger,
		s.configuration.Tunnel.BindIP,
		s.linkBroker,
		s.configuration.Tunnel.HTTPListenAddress != "",
		s.configuration.HTTP,
		s.configuration.UDP,
		sourceFilter,
	)
	defer s.proxyRegistry.Close()
	defer cancelSessions()
	httpErrors := make(chan error, 1)
	if s.configuration.Tunnel.HTTPListenAddress != "" {
		httpListener, listenError := (&net.ListenConfig{}).Listen(
			ctx,
			"tcp",
			s.configuration.Tunnel.HTTPListenAddress,
		)
		if listenError != nil {
			return fmt.Errorf(
				"listen for HTTP proxy requests on %q: %w",
				s.configuration.Tunnel.HTTPListenAddress,
				listenError,
			)
		}
		if s.configuration.Security.HTTPClientIPHeader == "" {
			httpListener = ipfilter.WrapListener(httpListener, sourceFilter)
		}
		httpProtocols := new(http.Protocols)
		httpProtocols.SetHTTP1(true)
		httpProtocols.SetUnencryptedHTTP2(true)
		httpServer := &http.Server{
			Handler: ipfilter.HTTPHandler(
				sourceFilter,
				s.configuration.Security.HTTPClientIPHeader,
				s.proxyRegistry,
			),
			ReadHeaderTimeout: s.configuration.HTTP.ReadHeaderTimeout,
			MaxHeaderBytes:    s.configuration.HTTP.MaxHeaderBytes,
			Protocols:         httpProtocols,
			ConnContext:       ipfilter.HTTPConnectionContext,
		}
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			serveError := httpServer.Serve(httpListener)
			if serveError != nil && !errors.Is(serveError, http.ErrServerClosed) {
				httpErrors <- serveError
				transportServer.Close()
			}
		}()
		defer func() {
			shutdownContext, cancel := context.WithTimeout(
				context.Background(),
				s.configuration.HTTP.GracefulShutdownTimeout,
			)
			defer cancel()
			_ = httpServer.Shutdown(shutdownContext)
		}()
	}
	sessions.Add(1)
	go func() {
		defer sessions.Done()
		s.monitorClients(sessionContext)
	}()

	for {
		inbound, err := transportServer.Accept(ctx)
		if err != nil {
			select {
			case httpError := <-httpErrors:
				return fmt.Errorf("serve HTTP proxy requests: %w", httpError)
			default:
			}
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.logger.TraceWithField(
			"client transport stream accepted",
			"remote_address",
			inbound.RemoteAddress,
		)

		sessions.Add(1)
		go func(accepted transport.Inbound) {
			defer sessions.Done()
			if err := s.handleConnection(sessionContext, accepted); err != nil &&
				!errors.Is(err, io.EOF) &&
				!errors.Is(err, net.ErrClosed) &&
				sessionContext.Err() == nil {
				s.logger.Error("client connection ended", err)
			}
		}(inbound)
	}
}

func (s *Service) handleConnection(ctx context.Context, inbound transport.Inbound) error {
	connection := inbound.Stream
	defer connection.Close()

	stopContextClose := context.AfterFunc(ctx, func() {
		connection.Close()
	})
	defer stopContextClose()

	if inbound.Role == protocol.RoleData {
		return s.handleDataConnection(ctx, connection)
	}
	if inbound.Role != protocol.RoleControl {
		return fmt.Errorf("unsupported connection role %d", inbound.Role)
	}
	if err := connection.SetDeadline(time.Now().Add(controlHelloTimeout)); err != nil {
		return fmt.Errorf("set control hello deadline: %w", err)
	}

	envelope, err := protocol.ReadControl(connection)
	if err != nil {
		return err
	}
	if envelope.Type != protocol.MessageClientHello {
		return fmt.Errorf("expected %s, got %s", protocol.MessageClientHello, envelope.Type)
	}
	var clientHello protocol.ClientHello
	if err := protocol.DecodePayload(envelope, &clientHello); err != nil {
		return err
	}
		if !coll.SliceContains(clientHello.Capabilities, "json-control") {
		return errors.New("client does not support json-control capability")
	}
	if err := config.ValidateClientID(clientHello.ClientID); err != nil {
		_ = writeSessionError(connection, protocol.SessionError{
			Code:      protocol.SessionErrorInvalidClientID,
			Message:   err.Error(),
			Retryable: false,
		})
		return err
	}

	sessionID, err := newSessionID()
	if err != nil {
		return err
	}
	sessionLogger := s.logger.WithFields(map[string]any{
		"client_id":  clientHello.ClientID,
		"session_id": sessionID,
	})
	sessionLogger.TraceWithFields("client hello received", map[string]any{
		"resume":            clientHello.ResumeSessionID != "",
		"remote_address":    inbound.RemoteAddress,
	})
	resumed, created, previousConnection, sessionError := s.clientRegistry.Register(
		clientHello.ClientID,
		clientHello.ResumeSessionID,
		sessionID,
		connection,
		time.Now(),
	)
	if sessionError != nil {
		if err := writeSessionError(connection, *sessionError); err != nil {
			sessionLogger.Error("failed to send client registration rejection", err)
			return nil
		}
		sessionLogger.InfoWithField(
			"client registration rejected",
			"error_code",
			sessionError.Code,
		)
		return nil
	}
	negotiatedCapabilities := negotiateCapabilities(clientHello.Capabilities)
	if err := protocol.WriteControl(connection, protocol.MessageServerHello, protocol.ServerHello{
		ClientID:     clientHello.ClientID,
		SessionID:    sessionID,
		Resumed:      resumed,
		Capabilities: negotiatedCapabilities,
	}); err != nil {
		if created {
			s.clientRegistry.Remove(clientHello.ClientID, sessionID)
		} else {
			s.clientRegistry.Disconnect(clientHello.ClientID, sessionID, time.Now())
		}
		sessionLogger.Error("failed to send server hello", err)
		return nil
	}
	if previousConnection != nil {
		previousConnection.Close()
	}
	writer := control.NewWriter(connection)
	s.proxyRegistry.Attach(clientHello.ClientID, sessionID, writer)
	defer func() {
		s.clientRegistry.Disconnect(clientHello.ClientID, sessionID, time.Now())
		s.proxyRegistry.Suspend(clientHello.ClientID, sessionID)
	}()

	if err := connection.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear control hello deadline: %w", err)
	}

	sessionLogger.InfoWithField("control session established", "resumed", resumed)
	gracefullyClosed, err := s.serveControlMessages(
		connection,
		clientHello.ClientID,
		sessionID,
		sessionLogger,
		writer,
		negotiatedCapabilities,
	)
	if gracefullyClosed {
		s.proxyRegistry.Remove(clientHello.ClientID, sessionID)
		s.clientRegistry.Remove(clientHello.ClientID, sessionID)
		sessionLogger.Info("control session closed by client")
	}
	if errors.Is(err, errProxyRegistrationRejected) {
		s.proxyRegistry.Remove(clientHello.ClientID, sessionID)
		s.clientRegistry.Remove(clientHello.ClientID, sessionID)
	}
	if err != nil &&
		!errors.Is(err, io.EOF) &&
		!errors.Is(err, net.ErrClosed) &&
		ctx.Err() == nil {
		sessionLogger.Error("control session ended", err)
	}
	return nil
}

func (s *Service) serveControlMessages(
	connection net.Conn,
	clientID string,
	sessionID string,
	sessionLogger *logging.Logger,
	writer *control.Writer,
	negotiatedCapabilities []string,
) (gracefullyClosed bool, err error) {
	for {
		envelope, err := protocol.ReadControl(connection)
		if err != nil {
			return false, err
		}
		switch envelope.Type {
		case protocol.MessagePing:
			var heartbeat protocol.Heartbeat
			if err := protocol.DecodePayload(envelope, &heartbeat); err != nil {
				return false, err
			}
			if !s.clientRegistry.Heartbeat(clientID, sessionID, time.Now()) {
				return false, errors.New("control session is no longer current")
			}
			sessionLogger.TraceWithField(
				"heartbeat ping received",
				"sequence",
				heartbeat.Sequence,
			)
			if err := writer.Write(protocol.MessagePong, heartbeat); err != nil {
				return false, err
			}
			sessionLogger.TraceWithField(
				"heartbeat pong sent",
				"sequence",
				heartbeat.Sequence,
			)
		case protocol.MessageCloseSession:
			var closeSession protocol.CloseSession
			if err := protocol.DecodePayload(envelope, &closeSession); err != nil {
				return false, err
			}
			if closeSession.SessionID != sessionID {
				return false, errors.New("close session ID does not match the current session")
			}
			sessionLogger.TraceWithField(
				"close session received",
				"reason",
				closeSession.Reason,
			)
			if err := writer.Write(protocol.MessageCloseAck, protocol.CloseAck{
				SessionID: sessionID,
			}); err != nil {
				return true, err
			}
			sessionLogger.Trace("close acknowledgment sent")
			return true, nil
		case protocol.MessageSyncProxies:
			var request protocol.SyncProxies
			if err := protocol.DecodePayload(envelope, &request); err != nil {
				return false, err
			}
			for _, declaration := range request.Proxies {
				if !coll.SliceContains(
					negotiatedCapabilities,
					string(declaration.Type),
				) {
					return false, fmt.Errorf("%s proxy registration requires a negotiated capability", declaration.Type)
				}
			}
			result := s.proxyRegistry.Sync(
				clientID,
				sessionID,
				envelope.RequestID,
				request,
			)
			if err := writer.WriteResponse(
				protocol.MessageSyncResult,
				envelope.RequestID,
				result,
			); err != nil {
				return false, err
			}
			if result.Status == protocol.ProxySyncStatusRejected {
				sessionLogger.InfoWithField(
					"proxy registration rejected",
					"error_code",
					result.Error.Code,
				)
				return false, errProxyRegistrationRejected
			}
			s.proxyRegistry.Activate(clientID, sessionID)
			sessionLogger.InfoWithField(
				"proxy registration applied",
				"revision",
				result.Revision,
			)
		case protocol.MessageLinkFailed:
			var failure protocol.LinkFailed
			if err := protocol.DecodePayload(envelope, &failure); err != nil {
				return false, err
			}
			s.linkBroker.ReportFailure(clientID, sessionID, failure)
			sessionLogger.WithField("link_id", failure.LinkID).TraceWithField(
				"proxy link setup failed",
				"error_code",
				failure.Code,
			)
		default:
			return false, fmt.Errorf("unsupported control message %q", envelope.Type)
		}
	}
}

func (s *Service) monitorClients(ctx context.Context) {
	ticker := time.NewTicker(clientMonitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			suspendedClients, expiredClients := s.clientRegistry.Sweep(
				now,
				controlHeartbeatTimeout,
				clientRecoveryWindow,
			)
			for _, suspended := range suspendedClients {
				s.proxyRegistry.Suspend(suspended.ClientID, suspended.SessionID)
				s.logger.WithFields(map[string]any{
					"client_id":  suspended.ClientID,
					"session_id": suspended.SessionID,
				}).Info("client suspended")
			}
			for _, expired := range expiredClients {
				s.proxyRegistry.Remove(expired.ClientID, expired.SessionID)
				if expired.Connection != nil {
					expired.Connection.Close()
				}
				s.logger.WithFields(map[string]any{
					"client_id":  expired.ClientID,
					"session_id": expired.SessionID,
				}).Info("client expired")
			}
		}
	}
}

func (s *Service) handleDataConnection(ctx context.Context, connection net.Conn) error {
	if err := connection.SetDeadline(time.Now().Add(dataBindTimeout)); err != nil {
		return fmt.Errorf("set TCP data bind deadline: %w", err)
	}
	envelope, err := protocol.ReadControl(connection)
	if err != nil {
		return err
	}
	if envelope.Type != protocol.MessageBindLink {
		return fmt.Errorf("expected %s, got %s", protocol.MessageBindLink, envelope.Type)
	}
	var binding protocol.BindLink
	if err := protocol.DecodePayload(envelope, &binding); err != nil {
		return err
	}
	return s.linkBroker.Bind(ctx, connection, binding)
}

func writeSessionError(connection net.Conn, sessionError protocol.SessionError) error {
	return protocol.WriteControl(connection, protocol.MessageSessionError, sessionError)
}

func negotiateCapabilities(clientCapabilities []string) []string {
	supported := map[string]struct{}{
		"tcp":          {},
		"udp":          {},
		"http":         {},
		"json-control": {},
	}
	negotiated := coll.SliceFilter(
		clientCapabilities,
		func(capability string) bool {
			_, supportedCapability := supported[capability]
			return supportedCapability
		},
	)
	if negotiated == nil {
		return []string{}
	}
	return negotiated
}

func newSessionID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
