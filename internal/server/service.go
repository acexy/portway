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
	"sync"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/consts"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

var errProxyRegistrationRejected = errors.New("TCP proxy registration rejected")

// Service manages the server process lifecycle.
//
// It owns the client listener and control session lifecycles. Proxy registration
// will be implemented in a later iteration.
type Service struct {
	logger         *logging.Logger
	configuration  config.ServerConfig
	clientRegistry *clientRegistry
	tcpProxyManager *tcpProxyManager
}

// NewService creates a server service.
func NewService(logger *logging.Logger, configuration config.ServerConfig) *Service {
	return &Service{
		logger:         logger,
		configuration:  configuration,
		clientRegistry: newClientRegistry(),
	}
}

// Run runs the server until the parent context is canceled.
func (s *Service) Run(ctx context.Context) error {
	s.logger.InfoWithField("server started", "listen_address", s.configuration.ListenAddress)
	defer s.logger.Info("server stopped")

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.configuration.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen on %q: %w", s.configuration.ListenAddress, err)
	}
	defer listener.Close()

	stopContextClose := context.AfterFunc(ctx, func() {
		listener.Close()
	})
	defer stopContextClose()

	var sessions sync.WaitGroup
	defer sessions.Wait()
	sessionContext, cancelSessions := context.WithCancel(ctx)
	s.tcpProxyManager = newTCPProxyManager(
		sessionContext,
		s.logger,
		s.configuration.ProxyBindIP,
	)
	defer s.tcpProxyManager.close()
	defer cancelSessions()
	connectionSlots := make(chan struct{}, consts.ServerMaxConcurrentConnections)

	sessions.Add(1)
	go func() {
		defer sessions.Done()
		s.monitorClients(sessionContext)
	}()

	for {
		rawConnection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept client connection: %w", err)
		}
		s.logger.TraceWithField(
			"client TCP connection accepted",
			"remote_address",
			rawConnection.RemoteAddr().String(),
		)

		select {
		case connectionSlots <- struct{}{}:
		default:
			rawConnection.Close()
			continue
		}

		sessions.Add(1)
		go func(connection net.Conn) {
			defer sessions.Done()
			defer func() {
				<-connectionSlots
			}()
			if err := s.handleConnection(sessionContext, connection); err != nil &&
				!errors.Is(err, io.EOF) &&
				!errors.Is(err, net.ErrClosed) &&
				sessionContext.Err() == nil {
				s.logger.Error("client connection ended", err)
			}
		}(rawConnection)
	}
}

func (s *Service) handleConnection(ctx context.Context, rawConnection net.Conn) error {
	defer rawConnection.Close()

	stopContextClose := context.AfterFunc(ctx, func() {
		rawConnection.Close()
	})
	defer stopContextClose()

	connection, role, err := transport.AcceptToken(
		ctx,
		rawConnection,
		s.configuration.Authentication.Token,
		protocol.RoleControl,
		protocol.RoleData,
	)
	if err != nil {
		return err
	}
	if role == protocol.RoleData {
		return s.handleDataConnection(ctx, connection)
	}
	if role != protocol.RoleControl {
		return fmt.Errorf("unsupported connection role %d", role)
	}
	if err := connection.SetDeadline(time.Now().Add(consts.ServerControlHelloTimeout)); err != nil {
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
	if !hasCapability(clientHello.Capabilities, "json-control") {
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
		"remote_address":    rawConnection.RemoteAddr().String(),
	})
	resumed, created, previousConnection, sessionError := s.clientRegistry.register(
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
	if err := protocol.WriteControl(connection, protocol.MessageServerHello, protocol.ServerHello{
		ClientID:     clientHello.ClientID,
		SessionID:    sessionID,
		Resumed:      resumed,
		Capabilities: negotiateCapabilities(clientHello.Capabilities),
	}); err != nil {
		if created {
			s.clientRegistry.remove(clientHello.ClientID, sessionID)
		} else {
			s.clientRegistry.disconnect(clientHello.ClientID, sessionID, time.Now())
		}
		sessionLogger.Error("failed to send server hello", err)
		return nil
	}
	if previousConnection != nil {
		previousConnection.Close()
	}
	writer := newControlWriter(connection)
	s.tcpProxyManager.attach(clientHello.ClientID, sessionID, writer)
	defer func() {
		s.clientRegistry.disconnect(clientHello.ClientID, sessionID, time.Now())
		s.tcpProxyManager.suspend(clientHello.ClientID, sessionID)
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
	)
	if gracefullyClosed {
		s.tcpProxyManager.remove(clientHello.ClientID, sessionID)
		s.clientRegistry.remove(clientHello.ClientID, sessionID)
		sessionLogger.Info("control session closed by client")
	}
	if errors.Is(err, errProxyRegistrationRejected) {
		s.tcpProxyManager.remove(clientHello.ClientID, sessionID)
		s.clientRegistry.remove(clientHello.ClientID, sessionID)
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
	writer *controlWriter,
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
			if !s.clientRegistry.heartbeat(clientID, sessionID, time.Now()) {
				return false, errors.New("control session is no longer current")
			}
			sessionLogger.TraceWithField(
				"heartbeat ping received",
				"sequence",
				heartbeat.Sequence,
			)
			if err := writer.write(protocol.MessagePong, heartbeat); err != nil {
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
			if err := writer.write(protocol.MessageCloseAck, protocol.CloseAck{
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
			result := s.tcpProxyManager.syncProxies(
				clientID,
				sessionID,
				envelope.RequestID,
				request,
			)
			if err := writer.writeResponse(
				protocol.MessageSyncResult,
				envelope.RequestID,
				result,
			); err != nil {
				return false, err
			}
			if result.Status == protocol.ProxySyncStatusRejected {
				sessionLogger.InfoWithField(
					"TCP proxy registration rejected",
					"error_code",
					result.Error.Code,
				)
				return false, errProxyRegistrationRejected
			}
			s.tcpProxyManager.activate(clientID, sessionID)
			sessionLogger.InfoWithField(
				"TCP proxy registration applied",
				"revision",
				result.Revision,
			)
		case protocol.MessageLinkFailed:
			var failure protocol.LinkFailed
			if err := protocol.DecodePayload(envelope, &failure); err != nil {
				return false, err
			}
			s.tcpProxyManager.reportLinkFailure(clientID, sessionID, failure)
			sessionLogger.WithField("link_id", failure.LinkID).TraceWithField(
				"TCP link setup failed",
				"error_code",
				failure.Code,
			)
		default:
			return false, fmt.Errorf("unsupported control message %q", envelope.Type)
		}
	}
}

func (s *Service) monitorClients(ctx context.Context) {
	ticker := time.NewTicker(consts.ServerClientMonitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			suspendedClients, expiredClients := s.clientRegistry.sweep(
				now,
				consts.ServerControlHeartbeatTimeout,
				consts.ServerClientRecoveryWindow,
			)
			for _, suspended := range suspendedClients {
				s.tcpProxyManager.suspend(suspended.clientID, suspended.sessionID)
				s.logger.WithFields(map[string]any{
					"client_id":  suspended.clientID,
					"session_id": suspended.sessionID,
				}).Info("client suspended")
			}
			for _, expired := range expiredClients {
				s.tcpProxyManager.remove(expired.clientID, expired.sessionID)
				if expired.connection != nil {
					expired.connection.Close()
				}
				s.logger.WithFields(map[string]any{
					"client_id":  expired.clientID,
					"session_id": expired.sessionID,
				}).Info("client expired")
			}
		}
	}
}

func (s *Service) handleDataConnection(ctx context.Context, connection net.Conn) error {
	if err := connection.SetDeadline(time.Now().Add(consts.TCPDataBindTimeout)); err != nil {
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
	logger := s.logger.WithFields(map[string]any{
		"client_id":  binding.ClientID,
		"session_id": binding.SessionID,
		"link_id":    binding.LinkID,
	})
	return s.tcpProxyManager.handleDataStream(ctx, connection, binding, logger)
}

func writeSessionError(connection net.Conn, sessionError protocol.SessionError) error {
	return protocol.WriteControl(connection, protocol.MessageSessionError, sessionError)
}

func hasCapability(capabilities []string, expected string) bool {
	for _, capability := range capabilities {
		if capability == expected {
			return true
		}
	}
	return false
}

func negotiateCapabilities(clientCapabilities []string) []string {
	supported := map[string]struct{}{
		"tcp":          {},
		"json-control": {},
	}
	negotiated := make([]string, 0, len(clientCapabilities))
	for _, capability := range clientCapabilities {
		if _, ok := supported[capability]; ok {
			negotiated = append(negotiated, capability)
		}
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
