// Package client provides the Portway client runtime.
package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
	transportfactory "github.com/acexy/portway/internal/transport/factory"
)

type remoteSessionError struct {
	code      protocol.SessionErrorCode
	message   string
	retryable bool
}

type proxyRegistrationError struct {
	code      protocol.ProxyErrorCode
	proxyName string
	message   string
}

func (registrationError *proxyRegistrationError) Error() string {
	return fmt.Sprintf(
		"TCP proxy registration rejected: proxy=%q code=%s message=%s",
		registrationError.proxyName,
		registrationError.code,
		registrationError.message,
	)
}

func (sessionError *remoteSessionError) Error() string {
	return fmt.Sprintf("server rejected control session: %s: %s", sessionError.code, sessionError.message)
}

// Service manages the client process lifecycle.
//
// It owns the control connection, reconnect lifecycle, proxy registration,
// and session-scoped TCP links.
type Service struct {
	logger        *logging.Logger
	configuration config.ClientConfig
	transport     transport.Client
}

// NewService creates a client service.
func NewService(logger *logging.Logger, configuration config.ClientConfig) *Service {
	return &Service{
		logger:        logger.WithField("client_id", configuration.ClientID),
		configuration: configuration,
	}
}

// Run runs the client until the parent context is canceled.
func (s *Service) Run(ctx context.Context) error {
	transportClient, err := transportfactory.NewClient(s.configuration)
	if err != nil {
		return err
	}
	s.transport = transportClient
	s.logger.InfoWithField(
		"client started",
		"server_address",
		s.configuration.Transport.ServerAddress,
	)
	defer s.logger.Info("client stopped")

	reconnectDelay := initialReconnectDelay
	sessionID := ""
	var disconnectedAt time.Time

	for {
		attemptLogger := s.logger
		if sessionID != "" {
			attemptLogger = attemptLogger.WithField("session_id", sessionID)
		}
		attemptLogger.TraceWithField(
			"starting control connection attempt",
			"resume",
			sessionID != "",
		)

		if sessionID != "" &&
			!disconnectedAt.IsZero() &&
			time.Since(disconnectedAt) >= sessionRecoveryWindow {
			s.logger.InfoWithField("client session recovery window expired", "session_id", sessionID)
			sessionID = ""
			disconnectedAt = time.Time{}
		}

		establishedSessionID, established, err := s.runControlSession(ctx, sessionID)
		if ctx.Err() != nil {
			return nil
		}
		if transport.IsPermanent(err) {
			return err
		}
		var registrationError *proxyRegistrationError
		if errors.As(err, &registrationError) {
			return err
		}
		if established {
			sessionID = establishedSessionID
			disconnectedAt = time.Now()
			reconnectDelay = initialReconnectDelay
		}

		var sessionError *remoteSessionError
		if errors.As(err, &sessionError) {
			switch sessionError.code {
			case protocol.SessionErrorSessionExpired:
				sessionID = ""
				disconnectedAt = time.Time{}
				reconnectDelay = initialReconnectDelay
				continue
			case protocol.SessionErrorResumeSessionMismatch,
				protocol.SessionErrorInvalidClientID:
				return err
			}
			if !sessionError.retryable {
				return err
			}
		}
		attemptLogger.Error("control session ended", err)

		actualReconnectDelay := reconnectDelayWithJitter(reconnectDelay)
		attemptLogger.TraceWithField(
			"waiting before control connection retry",
			"delay",
			actualReconnectDelay,
		)
		if !waitForRetry(ctx, actualReconnectDelay) {
			return nil
		}
		reconnectDelay = min(reconnectDelay*2, maximumReconnectDelay)
	}
}

func (s *Service) runControlSession(
	ctx context.Context,
	resumeSessionID string,
) (sessionID string, established bool, err error) {
	transportSession, err := s.transport.Connect(ctx)
	if err != nil {
		return "", false, err
	}
	defer transportSession.Close()
	connection := transportSession.ControlStream()

	stopHelloContextClose := context.AfterFunc(ctx, func() {
		connection.Close()
	})
	defer stopHelloContextClose()

	if err := connection.SetDeadline(time.Now().Add(controlHelloTimeout)); err != nil {
		return "", false, fmt.Errorf("set control hello deadline: %w", err)
	}
	if err := protocol.WriteControl(connection, protocol.MessageClientHello, protocol.ClientHello{
		ClientID:        s.configuration.ClientID,
		ResumeSessionID: resumeSessionID,
		Capabilities:    []string{"tcp", "udp", "http", "json-control"},
	}); err != nil {
		return "", false, err
	}
	s.logger.TraceWithField(
		"client hello sent",
		"resume",
		resumeSessionID != "",
	)

	envelope, err := protocol.ReadControl(connection)
	if err != nil {
		return "", false, classifyControlProtocolError(err)
	}
	if envelope.Type == protocol.MessageSessionError {
		return "", false, decodeRemoteSessionError(envelope)
	}
	if envelope.Type != protocol.MessageServerHello {
		return "", false, fmt.Errorf(
			"%w: expected %s, got %s",
			transport.ErrProtocol,
			protocol.MessageServerHello,
			envelope.Type,
		)
	}
	var serverHello protocol.ServerHello
	if err := protocol.DecodePayload(envelope, &serverHello); err != nil {
		return "", false, fmt.Errorf("%w: %w", transport.ErrProtocol, err)
	}
	if serverHello.ClientID != s.configuration.ClientID {
		return "", false, fmt.Errorf(
			"%w: server returned unexpected client ID: expected %q, got %q",
			transport.ErrProtocol,
			s.configuration.ClientID,
			serverHello.ClientID,
		)
	}
	if serverHello.SessionID == "" {
		return "", false, fmt.Errorf(
			"%w: server returned an empty session ID",
			transport.ErrProtocol,
		)
	}
	if !coll.SliceContains(serverHello.Capabilities, "json-control") {
		return "", false, fmt.Errorf(
			"%w: server did not negotiate json-control capability",
			transport.ErrProtocol,
		)
	}
	writer := control.NewWriter(connection)
	if err := connection.SetDeadline(time.Now().Add(controlHelloTimeout)); err != nil {
		return "", false, fmt.Errorf("set proxy registration deadline: %w", err)
	}
	if err := s.syncProxies(connection, writer); err != nil {
		return "", false, err
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return "", false, fmt.Errorf("clear control hello deadline: %w", err)
	}
	stopHelloContextClose()

	sessionLogger := s.logger.WithField("session_id", serverHello.SessionID)
	sessionLogger.TraceWithField("server hello received", "resumed", serverHello.Resumed)
	sessionLogger.Info("control session established")
	return serverHello.SessionID, true, s.runControlLoop(
		ctx,
		connection,
		serverHello.SessionID,
		sessionLogger,
		writer,
		transportSession,
	)
}

func (s *Service) runControlLoop(
	ctx context.Context,
	connection net.Conn,
	sessionID string,
	sessionLogger *logging.Logger,
	writer *control.Writer,
	transportSession transport.ClientSession,
) error {
	sessionContext, cancelSession := context.WithCancel(ctx)
	defer cancelSession()

	// The reader remains available during the bounded graceful-close window
	// after the process context is canceled so it can deliver close_ack.
	readerContext, cancelReader := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelReader()
	messages := make(chan protocol.Envelope)
	readErrors := make(chan error, 1)
	go readControlMessages(readerContext, connection, messages, readErrors)
	linkManager := newLinkManager(
		sessionContext,
		sessionLogger,
		s.configuration,
		sessionID,
		writer,
		transportSession,
	)
	defer linkManager.close()

	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()
	watchdogTicker := time.NewTicker(heartbeatCheckInterval)
	defer watchdogTicker.Stop()

	lastPongAt := time.Now()
	var sentSequence uint64
	var acknowledgedSequence uint64
	for {
		select {
		case <-ctx.Done():
			linkManager.close()
			s.closeControlSession(
				connection,
				messages,
				readErrors,
				sessionID,
				sessionLogger,
				writer,
			)
			return nil
		case err := <-readErrors:
			return err
		case envelope, ok := <-messages:
			if !ok {
				return errors.New("control message reader stopped")
			}
			switch envelope.Type {
			case protocol.MessagePong:
				var heartbeat protocol.Heartbeat
				if err := protocol.DecodePayload(envelope, &heartbeat); err != nil {
					return classifyControlProtocolError(err)
				}
				if heartbeat.Sequence <= acknowledgedSequence || heartbeat.Sequence > sentSequence {
					return fmt.Errorf(
						"%w: unexpected heartbeat sequence %d",
						transport.ErrProtocol,
						heartbeat.Sequence,
					)
				}
				acknowledgedSequence = heartbeat.Sequence
				lastPongAt = time.Now()
				sessionLogger.TraceWithField(
					"heartbeat pong received",
					"sequence",
					heartbeat.Sequence,
				)
			case protocol.MessageSessionError:
				return decodeRemoteSessionError(envelope)
			case protocol.MessageOpenLink:
				var request protocol.OpenLink
				if err := protocol.DecodePayload(envelope, &request); err != nil {
					return classifyControlProtocolError(err)
				}
				linkManager.open(request)
				sessionLogger.WithField("link_id", request.LinkID).Trace(
					"open link received",
				)
			case protocol.MessageCancelLink:
				var cancellation protocol.CancelLink
				if err := protocol.DecodePayload(envelope, &cancellation); err != nil {
					return classifyControlProtocolError(err)
				}
				linkManager.cancelLink(cancellation.LinkID)
			default:
				return fmt.Errorf(
					"%w: unsupported control message %q",
					transport.ErrProtocol,
					envelope.Type,
				)
			}
		case <-heartbeatTicker.C:
			if sentSequence == math.MaxUint64 {
				return errors.New("heartbeat sequence exhausted")
			}
			sentSequence++
			if err := writer.Write(protocol.MessagePing, protocol.Heartbeat{
				Sequence: sentSequence,
			}); err != nil {
				return err
			}
			sessionLogger.TraceWithField("heartbeat ping sent", "sequence", sentSequence)
		case <-watchdogTicker.C:
			if time.Since(lastPongAt) >= heartbeatTimeout {
				return fmt.Errorf(
					"server heartbeat timed out after %s",
					heartbeatTimeout,
				)
			}
		}
	}
}

func (s *Service) closeControlSession(
	connection net.Conn,
	messages <-chan protocol.Envelope,
	readErrors <-chan error,
	sessionID string,
	sessionLogger *logging.Logger,
	writer *control.Writer,
) {
	if err := connection.SetDeadline(time.Now().Add(gracefulCloseTimeout)); err != nil {
		sessionLogger.Error("failed to set graceful close deadline", err)
		return
	}
	if err := writer.Write(protocol.MessageCloseSession, protocol.CloseSession{
		SessionID: sessionID,
		Reason:    protocol.CloseReasonClientShutdown,
	}); err != nil {
		sessionLogger.Error("failed to send close session", err)
		return
	}
	sessionLogger.Trace("close session sent")

	timer := time.NewTimer(gracefulCloseTimeout)
	defer timer.Stop()
	for {
		select {
		case envelope, ok := <-messages:
			if !ok {
				return
			}
			if envelope.Type != protocol.MessageCloseAck {
				continue
			}
			var acknowledgment protocol.CloseAck
			if err := protocol.DecodePayload(envelope, &acknowledgment); err != nil {
				sessionLogger.Error("failed to decode close acknowledgment", err)
				return
			}
			if acknowledgment.SessionID != sessionID {
				sessionLogger.Error(
					"close acknowledgment contained an unexpected session ID",
					errors.New("session ID mismatch"),
				)
			}
			sessionLogger.Trace("close acknowledgment received")
			return
		case <-readErrors:
			return
		case <-timer.C:
			return
		}
	}
}

func (s *Service) syncProxies(
	connection net.Conn,
	writer *control.Writer,
) error {
	requestID, err := newRequestID()
	if err != nil {
		return err
	}
	declarations := make([]protocol.ProxyDeclaration, 0, len(s.configuration.Proxies))
	for _, proxyConfiguration := range s.configuration.Proxies {
		declarations = append(declarations, protocol.ProxyDeclaration{
			Name:       proxyConfiguration.Name,
			Type:       protocol.ProxyType(proxyConfiguration.Type),
			RemotePort: proxyConfiguration.RemotePort,
			Domain:     proxyConfiguration.Domain,
		})
	}
	if err := writer.WriteRequest(
		protocol.MessageSyncProxies,
		requestID,
		protocol.SyncProxies{
			Revision: 1,
			Proxies:  declarations,
		},
	); err != nil {
		return err
	}
	envelope, err := protocol.ReadControl(connection)
	if err != nil {
		return classifyControlProtocolError(err)
	}
	if envelope.Type != protocol.MessageSyncResult || envelope.RequestID != requestID {
		return fmt.Errorf(
			"%w: expected %s response for request %q",
			transport.ErrProtocol,
			protocol.MessageSyncResult,
			requestID,
		)
	}
	var result protocol.SyncResult
	if err := protocol.DecodePayload(envelope, &result); err != nil {
		return classifyControlProtocolError(err)
	}
	if result.Status != protocol.ProxySyncStatusApplied {
		if result.Error == nil {
			return fmt.Errorf(
				"%w: proxy registration rejected without an error",
				transport.ErrProtocol,
			)
		}
		return &proxyRegistrationError{
			code:      result.Error.Code,
			proxyName: result.Error.ProxyName,
			message:   result.Error.Message,
		}
	}
	s.logger.InfoWithField("proxy registration applied", "revision", result.Revision)
	return nil
}

func newRequestID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func readControlMessages(
	ctx context.Context,
	connection net.Conn,
	messages chan<- protocol.Envelope,
	readErrors chan<- error,
) {
	defer close(messages)

	for {
		envelope, err := protocol.ReadControl(connection)
		if err != nil {
			select {
			case readErrors <- classifyControlProtocolError(err):
			case <-ctx.Done():
			}
			return
		}
		select {
		case messages <- envelope:
		case <-ctx.Done():
			return
		}
	}
}

func decodeRemoteSessionError(envelope protocol.Envelope) error {
	var response protocol.SessionError
	if err := protocol.DecodePayload(envelope, &response); err != nil {
		return classifyControlProtocolError(err)
	}
	return &remoteSessionError{
		code:      response.Code,
		message:   response.Message,
		retryable: response.Retryable,
	}
}

func classifyControlProtocolError(err error) error {
	if errors.Is(err, protocol.ErrInvalidControlMessage) {
		return fmt.Errorf("%w: %w", transport.ErrProtocol, err)
	}
	return err
}

func waitForRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func reconnectDelayWithJitter(delay time.Duration) time.Duration {
	var randomByte [1]byte
	if _, err := rand.Read(randomByte[:]); err != nil {
		return delay
	}

	jitterRange := 2*reconnectJitterPercent + 1
	jitterPercent := int(randomByte[0])%jitterRange - reconnectJitterPercent
	return delay + delay*time.Duration(jitterPercent)/100
}
