package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/buildinfo"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

func (s *Service) handleConnection(ctx context.Context, inbound transport.Inbound) error {
	return s.handleAdmittedConnection(ctx, inbound, func() {})
}

func (s *Service) handleAdmittedConnection(
	ctx context.Context,
	inbound transport.Inbound,
	releaseAdmission func(),
) error {
	connection := inbound.Stream
	defer connection.Close()

	stopContextClose := context.AfterFunc(ctx, func() {
		connection.Close()
	})
	defer stopContextClose()

	if inbound.Role == protocol.RoleData {
		return s.handleDataConnection(ctx, inbound, releaseAdmission)
	}
	if inbound.Role != protocol.RoleControl {
		return fmt.Errorf("unsupported connection role %d", inbound.Role)
	}
	if err := connection.SetDeadline(time.Now().Add(controlHelloTimeout)); err != nil {
		return fmt.Errorf("set control hello deadline: %w", err)
	}

	if err := protocol.WriteControl(
		connection,
		protocol.MessageServerIdentification,
		protocol.ServerIdentification{
			Product: protocol.ProductServer,
			Version: buildinfo.Current().Version,
		},
	); err != nil {
		return fmt.Errorf("write server identification: %w", err)
	}
	envelope, err := protocol.ReadControl(connection)
	if err != nil {
		return err
	}
	if envelope.Type != protocol.MessageClientIdentification {
		return fmt.Errorf(
			"expected %s, got %s",
			protocol.MessageClientIdentification,
			envelope.Type,
		)
	}
	var clientIdentification protocol.ClientIdentification
	if err := protocol.DecodePayload(envelope, &clientIdentification); err != nil {
		return err
	}
	if err := protocol.ValidateClientIdentification(clientIdentification); err != nil {
		return fmt.Errorf("validate client identification: %w", err)
	}

	envelope, err = protocol.ReadControl(connection)
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
	if inbound.Authentication.Mode != authentication.ModeShared &&
		(config.ValidateClientID(clientHello.ClientID) != nil ||
			clientHello.ClientID != inbound.Authentication.ClientID) {
		_ = writeSessionError(connection, protocol.SessionError{
			Code:      protocol.SessionErrorAuthenticationFailed,
			Message:   transport.ErrAuthentication.Error(),
			Retryable: false,
		})
		return transport.ErrAuthentication
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
		"client_id":      clientHello.ClientID,
		"session_id":     sessionID,
		"client_version": clientIdentification.Version,
		"platform":       string(clientIdentification.OS) + "-" + string(clientIdentification.Arch),
		"hostname":       clientIdentification.Hostname,
	})
	sessionLogger.TraceWithFields("client hello received", map[string]any{
		"resume":         clientHello.ResumeSessionID != "",
		"remote_address": inbound.RemoteAddress,
	})
	s.authenticationBarrier.RLock()
	if !s.authenticationStore.IsCurrent(inbound.Authentication) {
		s.authenticationBarrier.RUnlock()
		return transport.ErrAuthentication
	}
	resumed, created, previousConnection, sessionError := s.clientRegistry.RegisterAuthenticated(
		clientHello.ClientID,
		clientHello.ResumeSessionID,
		sessionID,
		connection,
		time.Now(),
		inbound.Authentication,
	)
	s.authenticationBarrier.RUnlock()
	if sessionError != nil {
		if err := writeSessionError(connection, *sessionError); err != nil {
			sessionLogger.Error("failed to send client registration rejection", err)
			return nil
		}
		sessionLogger.WithComponent("session").WarnWithFields(
			"client registration rejected",
			nil,
			map[string]any{
				"event":      "client_registration_rejected",
				"error_code": sessionError.Code,
			},
		)
		return nil
	}
	// The Session Registry now owns a bounded Initializing record, so this
	// connection no longer consumes the unaffiliated admission budget.
	releaseAdmission()
	negotiatedCapabilities := s.negotiateCapabilities(clientHello.Capabilities)
	if err := protocol.WriteControl(connection, protocol.MessageServerHello, protocol.ServerHello{
		ClientID:       clientHello.ClientID,
		ManagementMode: protocol.ManagementMode(inbound.Authentication.Mode),
		SessionID:      sessionID,
		Resumed:        resumed,
		Capabilities:   negotiatedCapabilities,
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
	if resumed {
		// Session registration changes ownership before the previous control
		// goroutine necessarily reaches its deferred cleanup. Suspend the old
		// generation explicitly so no Pending or Active Link crosses the resume.
		s.proxyRegistry.Suspend(clientHello.ClientID, clientHello.ResumeSessionID)
	}
	writer := control.NewWriter(connection)
	maxActiveLinks := 0
	if inbound.Authentication.Mode == authentication.ModeGoverned {
		governed, _ := s.configuration.governedClient(clientHello.ClientID)
		maxActiveLinks = governed.Permissions.Proxies.Limits.MaxActiveLinks
	}
	s.proxyRegistry.AttachAuthenticated(
		clientHello.ClientID,
		sessionID,
		writer,
		inbound.Authentication,
		maxActiveLinks,
	)
	recoverableSession := resumed
	defer func() {
		if recoverableSession {
			s.clientRegistry.Disconnect(clientHello.ClientID, sessionID, time.Now())
			s.proxyRegistry.Suspend(clientHello.ClientID, sessionID)
			if s.forwardRegistry != nil {
				s.forwardRegistry.Remove(clientHello.ClientID, sessionID)
			}
			return
		}
		s.clientRegistry.Remove(clientHello.ClientID, sessionID)
		s.proxyRegistry.Remove(clientHello.ClientID, sessionID)
		if s.forwardRegistry != nil {
			s.forwardRegistry.Remove(clientHello.ClientID, sessionID)
		}
	}()

	if err := connection.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear control hello deadline: %w", err)
	}
	if inbound.Authentication.Mode == authentication.ModeManaged {
		if err := s.initializeManagedSession(
			ctx,
			connection,
			clientHello.ClientID,
			sessionID,
			writer,
			inbound.Authentication,
		); err != nil {
			return err
		}
		recoverableSession = true
		defer s.unregisterManagedSession(clientHello.ClientID, sessionID)
	}

	initialProxySynchronizationRequired :=
		inbound.Authentication.Mode != authentication.ModeManaged
	if initialProxySynchronizationRequired {
		if err := connection.SetDeadline(time.Now().Add(controlHelloTimeout)); err != nil {
			return fmt.Errorf("set initial proxy synchronization deadline: %w", err)
		}
	}
	if !initialProxySynchronizationRequired {
		sessionLogger.WithComponent("session").InfoWithFields(
			"control session established",
			map[string]any{
				"event":   "control_session_established",
				"resumed": resumed,
			},
		)
	}
	gracefullyClosed, err := s.serveControlMessages(
		connection,
		clientHello.ClientID,
		sessionID,
		sessionLogger,
		writer,
		negotiatedCapabilities,
		inbound.Authentication.Mode,
		initialProxySynchronizationRequired,
		func() {
			recoverableSession = true
			sessionLogger.WithComponent("session").InfoWithFields(
				"control session established",
				map[string]any{
					"event":   "control_session_established",
					"resumed": resumed,
				},
			)
		},
		inbound.Authentication,
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
		sessionLogger.WarnWithFields(
			"control session disconnected",
			err,
			map[string]any{
				"event":  "control_session_disconnected",
				"reason": "recoverable_error",
			},
		)
	}
	return nil
}
