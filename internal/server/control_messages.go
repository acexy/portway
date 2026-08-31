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
	proxyregistry "github.com/acexy/portway/internal/proxy/registry"
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
			if authenticationMode == authentication.ModeManaged {
				return false, errors.New("managed clients cannot declare configuration")
			}
			var request protocol.SyncConfiguration
			if err := protocol.DecodePayload(envelope, &request); err != nil {
				return false, err
			}
			if len(request.Proxies) == 0 && len(request.Forwards) == 0 {
				return false, errors.New("complete configuration must not be empty")
			}
			if rejection := validateConfigurationCapabilities(
				request,
				negotiatedCapabilities,
			); rejection != nil {
				if err := writer.WriteResponse(
					protocol.MessageSyncConfigurationResult,
					envelope.RequestID,
					*rejection,
				); err != nil {
					return false, err
				}
				return false, errProxyRegistrationRejected
			}
			proxyRequest := proxyregistry.SyncRequest{
				Revision: request.Revision,
				Proxies:  request.Proxies,
			}
			if authenticationMode == authentication.ModeGoverned {
				if result := s.validateGovernedProxies(clientID, proxyRequest); result != nil {
					if err := writeConfigurationRejection(
						writer,
						envelope.RequestID,
						request.Revision,
						configurationProxyError(result.Error),
					); err != nil {
						return false, err
					}
					return false, errProxyRegistrationRejected
				}
			}
			if s.forwardRegistry == nil {
				return false, errors.New("Forward Registry is unavailable")
			}
			if forwardError := s.forwardRegistry.Validate(
				authenticationContext,
				request.Forwards,
			); forwardError != nil {
				if err := writeConfigurationRejection(
					writer,
					envelope.RequestID,
					request.Revision,
					configurationForwardError(forwardError),
				); err != nil {
					return false, err
				}
				return false, errProxyRegistrationRejected
			}
			proxyResult := s.proxyRegistry.SyncAllowEmpty(
				clientID,
				sessionID,
				envelope.RequestID,
				proxyRequest,
			)
			if proxyResult.Status == proxyregistry.SyncStatusRejected {
				if err := writeConfigurationRejection(
					writer,
					envelope.RequestID,
					request.Revision,
					configurationProxyError(proxyResult.Error),
				); err != nil {
					return false, err
				}
				return false, errProxyRegistrationRejected
			}
			maxActiveForwardLinks := 0
			if authenticationMode == authentication.ModeGoverned {
				governed, _ := s.configuration.governedClient(clientID)
				maxActiveForwardLinks = governed.Permissions.Forwards.Limits.MaxActiveLinks
			}
			forwardResults, forwardError := s.forwardRegistry.Sync(
				clientID,
				sessionID,
				writer,
				authenticationContext,
				maxActiveForwardLinks,
				request.Forwards,
			)
			if forwardError != nil {
				return false, errors.New("validated Forward synchronization failed")
			}
			if err := writer.WriteResponse(
				protocol.MessageSyncConfigurationResult,
				envelope.RequestID,
				protocol.SyncConfigurationResult{
					Revision: request.Revision,
					Status:   protocol.ConfigurationSyncStatusApplied,
					Proxies:  proxyResult.Proxies,
					Forwards: forwardResults,
				},
			); err != nil {
				return false, err
			}
			s.proxyRegistry.Activate(clientID, sessionID)
			if initialProxySynchronizationRequired {
				if !s.clientRegistry.Activate(clientID, sessionID, time.Now()) {
					return false, errors.New("initialized client session is no longer current")
				}
				if err := connection.SetDeadline(time.Time{}); err != nil {
					return false, fmt.Errorf("clear initial configuration deadline: %w", err)
				}
				initialProxySynchronizationRequired = false
			}
			if onProxySynchronizationApplied != nil {
				onProxySynchronizationApplied()
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

func validateConfigurationCapabilities(
	request protocol.SyncConfiguration,
	capabilities []protocol.Capability,
) *protocol.SyncConfigurationResult {
	for _, declaration := range request.Proxies {
		if !coll.SliceContains(capabilities, protocol.Capability(declaration.Type)) {
			return &protocol.SyncConfigurationResult{
				Revision: request.Revision,
				Status:   protocol.ConfigurationSyncStatusRejected,
				Error: &protocol.ConfigurationError{
					Code:         protocol.ConfigurationErrorProxyTypeNotAllowed,
					ResourceKind: protocol.ConfigurationResourceProxy,
					ResourceName: declaration.Name,
					Message:      "proxy capability is not negotiated",
				},
			}
		}
	}
	for _, declaration := range request.Forwards {
		capability := protocol.CapabilityTCPForward
		if declaration.Type == protocol.ForwardTypeUDP {
			capability = protocol.CapabilityUDPForward
		}
		if !coll.SliceContains(capabilities, capability) {
			return &protocol.SyncConfigurationResult{
				Revision: request.Revision,
				Status:   protocol.ConfigurationSyncStatusRejected,
				Error: &protocol.ConfigurationError{
					Code:         protocol.ConfigurationErrorForwardTypeNotAllowed,
					ResourceKind: protocol.ConfigurationResourceForward,
					ResourceName: declaration.Name,
					Message:      "Forward capability is not negotiated",
				},
			}
		}
	}
	return nil
}

func writeConfigurationRejection(
	writer *control.Writer,
	requestID string,
	revision uint64,
	rejection *protocol.ConfigurationError,
) error {
	return writer.WriteResponse(
		protocol.MessageSyncConfigurationResult,
		requestID,
		protocol.SyncConfigurationResult{
			Revision: revision,
			Status:   protocol.ConfigurationSyncStatusRejected,
			Error:    rejection,
		},
	)
}

func configurationProxyError(source *proxyregistry.Error) *protocol.ConfigurationError {
	if source == nil {
		return nil
	}
	return &protocol.ConfigurationError{
		Code: protocol.ConfigurationErrorCode(source.Code), Message: source.Message,
		ResourceKind: protocol.ConfigurationResourceProxy,
		ResourceName: source.ProxyName, Retryable: source.Retryable,
	}
}

func configurationForwardError(source *protocol.ForwardError) *protocol.ConfigurationError {
	if source == nil {
		return nil
	}
	return &protocol.ConfigurationError{
		Code: protocol.ConfigurationErrorCode(source.Code), Message: source.Message,
		ResourceKind: protocol.ConfigurationResourceForward,
		ResourceName: source.ForwardName, Retryable: source.Retryable,
	}
}
