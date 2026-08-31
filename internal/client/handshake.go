package client

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/buildinfo"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

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
		ClientID:        s.configuration.Authentication.ClientID,
		ResumeSessionID: resumeSessionID,
		Capabilities: []protocol.Capability{
			protocol.CapabilityTCP,
			protocol.CapabilityUDP,
			protocol.CapabilityHTTP,
			protocol.CapabilityJSONControl,
			protocol.CapabilityTCPForward,
			protocol.CapabilityUDPForward,
		},
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
		serverHello.ManagementMode == protocol.ManagementModeShared {
		if serverHello.ClientID != s.configuration.Authentication.ClientID {
			return "", false, fmt.Errorf(
				"%w: server returned unexpected client ID: expected %q, got %q",
				transport.ErrProtocol,
				s.configuration.Authentication.ClientID,
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
		if serverHello.ClientID != s.configuration.Authentication.ClientID {
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
	if !coll.SliceContains(serverHello.Capabilities, protocol.CapabilityJSONControl) {
		return "", false, fmt.Errorf(
			"%w: server did not negotiate json-control capability",
			transport.ErrProtocol,
		)
	}
	writer := control.NewWriter(connection)
	if err := connection.SetDeadline(time.Now().Add(controlHelloTimeout)); err != nil {
		return "", false, fmt.Errorf("set proxy registration deadline: %w", err)
	}
	var forwardRuntime *forwardManager
	switch serverHello.ManagementMode {
	case "", protocol.ManagementModeShared, protocol.ManagementModeGoverned:
		if err := validateLocalProxiesForManagementMode(
			serverHello.ManagementMode,
			len(s.configuration.Proxies),
			len(s.configuration.Forwards),
		); err != nil {
			return "", false, err
		}
		if len(s.configuration.Forwards) == 0 {
			if err := s.syncProxies(connection, writer); err != nil {
				return "", false, err
			}
		} else {
			if err := validateForwardCapabilities(
				s.configuration.Forwards,
				serverHello.Capabilities,
			); err != nil {
				return "", false, err
			}
			forwardRuntime, err = newForwardManager(
				ctx,
				s.logger,
				s.runtimeIdentity(),
				serverHello.SessionID,
				writer,
				transportSession,
				s.runtimeForwardSnapshot(),
			)
			if err != nil {
				return "", false, transport.Permanent(err)
			}
			defer func() { forwardRuntime.close() }()
			result, err := s.syncConfiguration(connection, writer)
			if err != nil {
				return "", false, err
			}
			if err := forwardRuntime.applyBindings(result.Forwards); err != nil {
				return "", false, fmt.Errorf("%w: %v", transport.ErrProtocol, err)
			}
			if err := forwardRuntime.start(); err != nil {
				return "", false, transport.Permanent(err)
			}
		}
	case protocol.ManagementModeManaged:
		if err := validateLocalProxiesForManagementMode(
			serverHello.ManagementMode,
			len(s.configuration.Proxies),
			len(s.configuration.Forwards),
		); err != nil {
			return "", false, err
		}
		forwardRuntime, err = s.receiveManagedConfiguration(
			ctx, connection, writer, serverHello.ClientID, serverHello.SessionID, transportSession,
		)
		if err != nil {
			return "", false, err
		}
		defer func() { forwardRuntime.close() }()
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
	sessionLogger.InfoWithFields("control session established", map[string]any{
		"event":   "control_session_established",
		"resumed": serverHello.Resumed,
	})
	return serverHello.SessionID, true, s.runControlLoop(
		ctx,
		connection,
		serverHello.SessionID,
		sessionLogger,
		writer,
		transportSession,
		serverHello.ManagementMode,
		forwardRuntime,
	)
}

func validateLocalProxiesForManagementMode(
	mode protocol.ManagementMode,
	proxyCount int,
	forwardCounts ...int,
) error {
	forwardCount := 0
	if len(forwardCounts) != 0 {
		forwardCount = forwardCounts[0]
	}
	switch mode {
	case "", protocol.ManagementModeShared, protocol.ManagementModeGoverned:
		if proxyCount == 0 && forwardCount == 0 {
			return transport.Permanent(errClientDeclaredProxiesRequired)
		}
	case protocol.ManagementModeManaged:
		if proxyCount != 0 || forwardCount != 0 {
			return transport.Permanent(errManagedLocalProxies)
		}
	}
	return nil
}

func validateForwardCapabilities(
	forwards []config.ForwardConfig,
	capabilities []protocol.Capability,
) error {
	for _, forward := range forwards {
		required := protocol.CapabilityTCPForward
		if forward.Type == protocol.ForwardTypeUDP {
			required = protocol.CapabilityUDPForward
		}
		if !coll.SliceContains(capabilities, required) {
			return transport.Permanent(fmt.Errorf(
				"server did not negotiate %s for Forward %q",
				required,
				forward.Name,
			))
		}
	}
	return nil
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
		protocol.SessionErrorSessionExpired,
		protocol.SessionErrorServerCapacityReached:
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
