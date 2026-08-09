package server

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/acexy/golang-toolkit/util/coll"

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
) (gracefullyClosed bool, err error) {
	for {
		envelope, err := protocol.ReadControl(connection)
		if err != nil {
			return false, err
		}
		if initialProxySynchronizationRequired &&
			envelope.Type != protocol.MessageSyncProxies {
			return false, fmt.Errorf(
				"expected initial %s, got %s",
				protocol.MessageSyncProxies,
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
		case protocol.MessageSyncProxies:
			if authenticationMode == authentication.ModeManaged {
				return false, errors.New("managed clients cannot declare proxy configuration")
			}
			var request protocol.SyncProxies
			if err := protocol.DecodePayload(envelope, &request); err != nil {
				return false, err
			}
			for _, declaration := range request.Proxies {
				if !coll.SliceContains(
					negotiatedCapabilities,
					protocol.Capability(declaration.Type),
				) {
					return false, fmt.Errorf("%s proxy registration requires a negotiated capability", declaration.Type)
				}
			}
			if authenticationMode == authentication.ModeGoverned {
				if result := s.validateGovernedProxies(clientID, request); result != nil {
					if err := writer.WriteResponse(
						protocol.MessageSyncResult,
						envelope.RequestID,
						*result,
					); err != nil {
						return false, err
					}
					return false, errProxyRegistrationRejected
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
				sessionLogger.WithComponent("proxy_registry").WarnWithFields(
					"proxy registration rejected",
					nil,
					map[string]any{
						"event":      "proxy_registration_rejected",
						"error_code": result.Error.Code,
					},
				)
				return false, errProxyRegistrationRejected
			}
			s.proxyRegistry.Activate(clientID, sessionID)
			if initialProxySynchronizationRequired {
				if !s.clientRegistry.Activate(clientID, sessionID, time.Now()) {
					return false, errors.New("initialized client session is no longer current")
				}
				if err := connection.SetDeadline(time.Time{}); err != nil {
					return false, fmt.Errorf(
						"clear initial proxy synchronization deadline: %w",
						err,
					)
				}
				initialProxySynchronizationRequired = false
			}
			if onProxySynchronizationApplied != nil {
				onProxySynchronizationApplied()
			}
			sessionLogger.WithComponent("proxy_registry").InfoWithFields(
				"proxy registration applied",
				map[string]any{
					"event":       "proxy_registration_applied",
					"revision":    result.Revision,
					"proxy_count": len(request.Proxies),
				},
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
