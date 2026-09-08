package server

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
)

func (s *Service) serveControlMessages(
	connection net.Conn,
	clientID string,
	sessionID string,
	sessionLogger *logging.Logger,
	writer *control.Writer,
	negotiatedCapabilities []protocol.Capability,
	authenticationMode authentication.Mode,
	initialProxySynchronizationRequired bool,
	onProxySynchronizationApplied func(),
	authenticationContexts ...authentication.Context,
) (gracefullyClosed bool, err error) {
	authenticationContext := authentication.Context{
		Mode:     authenticationMode,
		ClientID: clientID,
	}
	if len(authenticationContexts) != 0 {
		authenticationContext = authenticationContexts[0]
	}
	configurationSession := configurationSyncSession{
		clientID: clientID, sessionID: sessionID, writer: writer,
		mode: authenticationMode, authentication: authenticationContext,
		capabilities: negotiatedCapabilities,
	}
	defer s.clearConfigurationSync(clientID, sessionID)
	finishConfiguration := func(requestID string, result protocol.SyncConfigurationResult) error {
		if err := writer.WriteResponse(
			protocol.MessageSyncConfigurationResult,
			requestID,
			result,
		); err != nil {
			return err
		}
		s.proxyRegistry.Activate(clientID, sessionID)
		if initialProxySynchronizationRequired {
			if !s.clientRegistry.Activate(clientID, sessionID, time.Now()) {
				return errors.New("initialized client session is no longer current")
			}
			if err := connection.SetDeadline(time.Time{}); err != nil {
				return fmt.Errorf("clear initial configuration deadline: %w", err)
			}
			initialProxySynchronizationRequired = false
		}
		if onProxySynchronizationApplied != nil {
			onProxySynchronizationApplied()
		}
		return nil
	}
	for {
		envelope, err := protocol.ReadControl(connection)
		if err != nil {
			return false, err
		}
		if initialProxySynchronizationRequired && envelope.Type != protocol.MessageSyncConfiguration {
			return false, fmt.Errorf(
				"expected initial %s, got %s",
				protocol.MessageSyncConfiguration,
				envelope.Type,
			)
		}
		switch envelope.Type {
		case protocol.MessagePing:
			var heartbeat protocol.Heartbeat
			if err := protocol.DecodePayload(envelope, &heartbeat); err != nil {
				return false, err
			}
			heartbeatAccepted, reactivated := s.clientRegistry.Heartbeat(
				clientID,
				sessionID,
				heartbeat.Sequence,
				time.Now(),
			)
			if !heartbeatAccepted {
				return false, errors.New("control session is no longer current")
			}
			if reactivated {
				s.proxyRegistry.Activate(clientID, sessionID)
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
		case protocol.MessageSyncConfiguration:
			result, err := s.synchronizeConfiguration(configurationSession, envelope)
			if err != nil {
				return false, err
			}
			if err := finishConfiguration(envelope.RequestID, result); err != nil {
				return false, err
			}
		case protocol.MessageRequestForwardLink:
			var request protocol.RequestForwardLink
			if err := protocol.DecodePayload(envelope, &request); err != nil {
				return false, err
			}
			if s.forwardRegistry == nil {
				return false, errors.New("Forward Registry is unavailable")
			}
			offer := s.forwardRegistry.Offer(clientID, sessionID, request)
			if err := writer.Write(protocol.MessageForwardLinkOffer, offer); err != nil {
				return false, err
			}
		case protocol.MessageCancelForwardLink:
			var cancellation protocol.CancelForwardLink
			if err := protocol.DecodePayload(envelope, &cancellation); err != nil {
				return false, err
			}
			s.linkBroker.CancelLink(cancellation.LinkID)
		case protocol.MessageForwardLinkFailed:
			var failure protocol.ForwardLinkFailed
			if err := protocol.DecodePayload(envelope, &failure); err != nil {
				return false, err
			}
			s.linkBroker.ReportFailure(clientID, sessionID, protocol.LinkFailed{
				LinkID: failure.LinkID,
				Code:   failure.Code,
			})
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
		case protocol.MessageManagedConfigPrepared,
			protocol.MessageManagedConfigApplied:
			if authenticationMode != authentication.ModeManaged {
				return false, errors.New("non-managed client sent managed configuration status")
			}
			var status protocol.ManagedConfigStatus
			if err := protocol.DecodePayload(envelope, &status); err != nil {
				return false, err
			}
			if !s.publishManagedStatus(
				clientID,
				sessionID,
				envelope.Type,
				status,
			) {
				return false, errors.New("unexpected managed configuration status")
			}
		default:
			return false, fmt.Errorf("unsupported control message %q", envelope.Type)
		}
	}
}
