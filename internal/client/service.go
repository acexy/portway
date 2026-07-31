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
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/buildinfo"
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
	retryable bool
}

var errManagedLocalProxies = errors.New(
	"managed clients cannot configure local proxies",
)

var errClientDeclaredProxiesRequired = errors.New(
	"shared and governed clients require at least one local proxy",
)

func (registrationError *proxyRegistrationError) Error() string {
	return fmt.Sprintf(
		"proxy registration rejected: proxy=%q code=%s message=%s",
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
	logger          *logging.Logger
	configuration   config.ClientConfig
	transport       transport.Client
	identification  protocol.ClientIdentification
	runtimeMutex    sync.RWMutex
	runtimeClientID string
	runtimeProxies  []config.ProxyConfig
	managedMutex    sync.RWMutex
	managedStatus   protocol.ManagedConfigStatus
}

// NewService creates a client service.
func NewService(logger *logging.Logger, configuration config.ClientConfig) *Service {
	return &Service{
		logger:          logger.WithField("client_id", configuration.ClientID),
		configuration:   configuration,
		runtimeClientID: configuration.ClientID,
		runtimeProxies:  append([]config.ProxyConfig(nil), configuration.Proxies...),
	}
}

// Run runs the client until the parent context is canceled.
func (s *Service) Run(ctx context.Context) error {
	identification, err := currentClientIdentification()
	if err != nil {
		return err
	}
	s.identification = identification

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
			if !registrationError.retryable {
				return err
			}
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
			case protocol.SessionErrorClientIDRecoveryPending:
			case protocol.SessionErrorResumeSessionMismatch,
				protocol.SessionErrorInvalidClientID,
				protocol.SessionErrorClientIDAlreadyOnline:
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
	envelope, err := protocol.ReadControl(connection)
	if err != nil {
		return "", false, classifyControlProtocolError(err)
	}
	if envelope.Type != protocol.MessageServerIdentification {
		return "", false, fmt.Errorf(
			"%w: expected %s, got %s",
			transport.ErrProtocol,
			protocol.MessageServerIdentification,
			envelope.Type,
		)
	}
	var serverIdentification protocol.ServerIdentification
	if err := protocol.DecodePayload(envelope, &serverIdentification); err != nil {
		return "", false, fmt.Errorf("%w: %w", transport.ErrProtocol, err)
	}
	if err := protocol.ValidateServerIdentification(serverIdentification); err != nil {
		return "", false, fmt.Errorf("%w: %w", transport.ErrProtocol, err)
	}
	if err := protocol.WriteControl(
		connection,
		protocol.MessageClientIdentification,
		s.identification,
	); err != nil {
		return "", false, err
	}
	s.logger.TraceWithField(
		"server identification accepted",
		"server_version",
		serverIdentification.Version,
	)

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

	envelope, err = protocol.ReadControl(connection)
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
	if serverHello.ManagementMode == "" ||
		serverHello.ManagementMode == "shared_token" {
		if serverHello.ClientID != s.configuration.ClientID {
			return "", false, fmt.Errorf(
				"%w: server returned unexpected client ID: expected %q, got %q",
				transport.ErrProtocol,
				s.configuration.ClientID,
				serverHello.ClientID,
			)
		}
	} else {
		if err := config.ValidateClientID(serverHello.ClientID); err != nil {
			return "", false, fmt.Errorf(
				"%w: server returned invalid authenticated client ID",
				transport.ErrProtocol,
			)
		}
		if serverHello.ClientID != s.configuration.ClientID {
			return "", false, fmt.Errorf(
				"%w: server returned a client ID that does not match the configured identity",
				transport.ErrProtocol,
			)
		}
		s.setRuntimeClientID(serverHello.ClientID)
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
	switch serverHello.ManagementMode {
	case "", "shared_token", "governed":
		if err := validateLocalProxiesForManagementMode(
			serverHello.ManagementMode,
			len(s.configuration.Proxies),
		); err != nil {
			return "", false, err
		}
		if err := s.syncProxies(connection, writer); err != nil {
			return "", false, err
		}
	case "managed":
		if err := validateLocalProxiesForManagementMode(
			serverHello.ManagementMode,
			len(s.configuration.Proxies),
		); err != nil {
			return "", false, err
		}
		if err := s.receiveManagedConfiguration(connection, writer); err != nil {
			return "", false, err
		}
	default:
		return "", false, fmt.Errorf(
			"%w: server returned unsupported management mode %q",
			transport.ErrProtocol,
			serverHello.ManagementMode,
		)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return "", false, fmt.Errorf("clear control hello deadline: %w", err)
	}
	stopHelloContextClose()

	sessionLogger := s.logger.WithFields(map[string]any{
		"client_id":  serverHello.ClientID,
		"session_id": serverHello.SessionID,
	})
	sessionLogger.TraceWithField("server hello received", "resumed", serverHello.Resumed)
	sessionLogger.Info("control session established")
	return serverHello.SessionID, true, s.runControlLoop(
		ctx,
		connection,
		serverHello.SessionID,
		sessionLogger,
		writer,
		transportSession,
		serverHello.ManagementMode,
	)
}

func validateLocalProxiesForManagementMode(mode string, proxyCount int) error {
	switch mode {
	case "", "shared_token", "governed":
		if proxyCount == 0 {
			return transport.Permanent(errClientDeclaredProxiesRequired)
		}
	case "managed":
		if proxyCount != 0 {
			return transport.Permanent(errManagedLocalProxies)
		}
	}
	return nil
}

func (s *Service) receiveManagedConfiguration(
	connection net.Conn,
	writer *control.Writer,
) error {
	envelope, err := protocol.ReadControl(connection)
	if err != nil {
		return classifyControlProtocolError(err)
	}
	if envelope.Type != protocol.MessageManagedConfigPrepare {
		return fmt.Errorf(
			"%w: expected %s, got %s",
			transport.ErrProtocol,
			protocol.MessageManagedConfigPrepare,
			envelope.Type,
		)
	}
	var preparation protocol.ManagedConfigPrepare
	if err := protocol.DecodePayload(envelope, &preparation); err != nil {
		return classifyControlProtocolError(err)
	}
	proxies, status, err := validateManagedPreparation(preparation)
	if err != nil {
		return err
	}
	if err := writer.Write(protocol.MessageManagedConfigPrepared, status); err != nil {
		return err
	}
	envelope, err = protocol.ReadControl(connection)
	if err != nil {
		return classifyControlProtocolError(err)
	}
	if envelope.Type != protocol.MessageManagedConfigActivate {
		return fmt.Errorf(
			"%w: expected %s, got %s",
			transport.ErrProtocol,
			protocol.MessageManagedConfigActivate,
			envelope.Type,
		)
	}
	var activation protocol.ManagedConfigStatus
	if err := protocol.DecodePayload(envelope, &activation); err != nil {
		return classifyControlProtocolError(err)
	}
	if activation != status {
		return fmt.Errorf("%w: managed configuration activation mismatch", transport.ErrProtocol)
	}
	s.setRuntimeProxies(proxies)
	s.managedMutex.Lock()
	s.managedStatus = status
	s.managedMutex.Unlock()
	if err := writer.Write(protocol.MessageManagedConfigApplied, status); err != nil {
		return err
	}
	s.logger.InfoWithField("managed configuration applied", "revision", status.Revision)
	return nil
}

func validateManagedPreparation(
	preparation protocol.ManagedConfigPrepare,
) ([]config.ProxyConfig, protocol.ManagedConfigStatus, error) {
	if preparation.Revision == 0 || preparation.Digest == "" {
		return nil, protocol.ManagedConfigStatus{}, fmt.Errorf(
			"%w: invalid managed configuration generation",
			transport.ErrProtocol,
		)
	}
	digest, err := protocol.ManagedConfigurationDigest(preparation.Proxies)
	if err != nil {
		return nil, protocol.ManagedConfigStatus{}, fmt.Errorf(
			"encode managed configuration: %w",
			err,
		)
	}
	if digest != preparation.Digest {
		return nil, protocol.ManagedConfigStatus{}, fmt.Errorf(
			"%w: managed configuration digest mismatch",
			transport.ErrProtocol,
		)
	}
	proxies := make([]config.ProxyConfig, 0, len(preparation.Proxies))
	for _, managedProxy := range preparation.Proxies {
		proxies = append(proxies, config.ProxyConfig{
			Name:       managedProxy.Name,
			Type:       string(managedProxy.Type),
			LocalIP:    managedProxy.LocalIP,
			LocalPort:  managedProxy.LocalPort,
			RemotePort: managedProxy.RemotePort,
			Domain:     managedProxy.Domain,
		})
	}
	if err := config.ValidateManagedProxies(proxies); err != nil {
		return nil, protocol.ManagedConfigStatus{}, fmt.Errorf(
			"%w: validate managed configuration: %v",
			transport.ErrProtocol,
			err,
		)
	}
	status := protocol.ManagedConfigStatus{
		Revision: preparation.Revision,
		Digest:   preparation.Digest,
	}
	return proxies, status, nil
}

func currentClientIdentification() (protocol.ClientIdentification, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return protocol.ClientIdentification{}, fmt.Errorf("get client hostname: %w", err)
	}
	identification := protocol.ClientIdentification{
		Product:  protocol.ProductClient,
		Version:  buildinfo.Current().Version,
		OS:       protocol.OperatingSystem(runtime.GOOS),
		Arch:     protocol.Architecture(runtime.GOARCH),
		Hostname: hostname,
	}
	if err := protocol.ValidateClientIdentification(identification); err != nil {
		return protocol.ClientIdentification{}, fmt.Errorf(
			"build client identification: %w",
			err,
		)
	}
	return identification, nil
}

func (s *Service) runControlLoop(
	ctx context.Context,
	connection net.Conn,
	sessionID string,
	sessionLogger *logging.Logger,
	writer *control.Writer,
	transportSession transport.ClientSession,
	managementMode string,
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
		s.runtimeIdentity(),
		s.runtimeProxySnapshot(),
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
	var pendingManagedProxies []config.ProxyConfig
	var pendingManagedStatus *protocol.ManagedConfigStatus
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
			case protocol.MessageManagedConfigPrepare:
				if managementMode != "managed" {
					return fmt.Errorf(
						"%w: unmanaged session received managed configuration",
						transport.ErrProtocol,
					)
				}
				var preparation protocol.ManagedConfigPrepare
				if err := protocol.DecodePayload(envelope, &preparation); err != nil {
					return classifyControlProtocolError(err)
				}
				proxies, status, err := validateManagedPreparation(preparation)
				if err != nil {
					return err
				}
				if pendingManagedStatus != nil {
					if status != *pendingManagedStatus {
						return fmt.Errorf(
							"%w: conflicting managed configuration rollout is pending",
							transport.ErrProtocol,
						)
					}
					if err := writer.Write(
						protocol.MessageManagedConfigPrepared,
						status,
					); err != nil {
						return err
					}
					continue
				}
				s.managedMutex.RLock()
				currentStatus := s.managedStatus
				s.managedMutex.RUnlock()
				if status.Revision < currentStatus.Revision ||
					(status.Revision == currentStatus.Revision &&
						status.Digest != currentStatus.Digest) {
					return fmt.Errorf(
						"%w: stale or conflicting managed configuration revision",
						transport.ErrProtocol,
					)
				}
				pendingManagedProxies = proxies
				pendingManagedStatus = &status
				if err := writer.Write(
					protocol.MessageManagedConfigPrepared,
					status,
				); err != nil {
					return err
				}
			case protocol.MessageManagedConfigActivate:
				var activation protocol.ManagedConfigStatus
				if err := protocol.DecodePayload(envelope, &activation); err != nil {
					return classifyControlProtocolError(err)
				}
				if pendingManagedStatus == nil {
					s.managedMutex.RLock()
					currentStatus := s.managedStatus
					s.managedMutex.RUnlock()
					if activation != currentStatus {
						return fmt.Errorf(
							"%w: managed configuration activation has no preparation",
							transport.ErrProtocol,
						)
					}
					if err := writer.Write(
						protocol.MessageManagedConfigApplied,
						activation,
					); err != nil {
						return err
					}
					continue
				}
				if activation != *pendingManagedStatus {
					return fmt.Errorf(
						"%w: managed configuration activation mismatch",
						transport.ErrProtocol,
					)
				}
				s.setRuntimeProxies(pendingManagedProxies)
				linkManager.updateProxies(pendingManagedProxies)
				s.managedMutex.Lock()
				s.managedStatus = activation
				s.managedMutex.Unlock()
				if err := writer.Write(
					protocol.MessageManagedConfigApplied,
					activation,
				); err != nil {
					return err
				}
				pendingManagedProxies = nil
				pendingManagedStatus = nil
				sessionLogger.InfoWithField(
					"managed configuration applied",
					"revision",
					activation.Revision,
				)
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
	proxies := s.runtimeProxySnapshot()
	declarations := make([]protocol.ProxyDeclaration, 0, len(proxies))
	for _, proxyConfiguration := range proxies {
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
			retryable: result.Error.Retryable,
		}
	}
	s.logger.InfoWithField("proxy registration applied", "revision", result.Revision)
	return nil
}

func (s *Service) runtimeIdentity() string {
	s.runtimeMutex.RLock()
	defer s.runtimeMutex.RUnlock()
	return s.runtimeClientID
}

func (s *Service) setRuntimeClientID(clientID string) {
	s.runtimeMutex.Lock()
	s.runtimeClientID = clientID
	s.runtimeMutex.Unlock()
}

func (s *Service) runtimeProxySnapshot() []config.ProxyConfig {
	s.runtimeMutex.RLock()
	defer s.runtimeMutex.RUnlock()
	return append([]config.ProxyConfig(nil), s.runtimeProxies...)
}

func (s *Service) setRuntimeProxies(proxies []config.ProxyConfig) {
	s.runtimeMutex.Lock()
	s.runtimeProxies = append([]config.ProxyConfig(nil), proxies...)
	s.runtimeMutex.Unlock()
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
	if err := validateSessionErrorRetryable(response); err != nil {
		return err
	}
	if response.Code == protocol.SessionErrorAuthenticationFailed {
		return transport.ErrAuthentication
	}
	return &remoteSessionError{
		code:      response.Code,
		message:   response.Message,
		retryable: response.Retryable,
	}
}

func validateSessionErrorRetryable(response protocol.SessionError) error {
	var expected bool
	switch response.Code {
	case protocol.SessionErrorClientIDRecoveryPending,
		protocol.SessionErrorSessionExpired:
		expected = true
	case protocol.SessionErrorAuthenticationFailed,
		protocol.SessionErrorInvalidClientID,
		protocol.SessionErrorClientIDAlreadyOnline,
		protocol.SessionErrorResumeSessionMismatch:
		expected = false
	default:
		return nil
	}
	if response.Retryable != expected {
		return fmt.Errorf(
			"%w: session error %q has invalid retryable value",
			transport.ErrProtocol,
			response.Code,
		)
	}
	return nil
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
