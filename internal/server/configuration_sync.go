package server

import (
	"errors"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
	proxyregistry "github.com/acexy/portway/internal/proxy/registry"
)

// configurationSyncSession carries the authenticated scope of one control reader.
type configurationSyncSession struct {
	clientID       string
	sessionID      string
	writer         *control.Writer
	mode           authentication.Mode
	authentication authentication.Context
	capabilities   []protocol.Capability
}

// synchronizeConfiguration applies one complete declaration before session activation.
func (s *Service) synchronizeConfiguration(
	session configurationSyncSession,
	envelope protocol.Envelope,
) (protocol.SyncConfigurationResult, error) {
	if session.mode == authentication.ModeManaged {
		return protocol.SyncConfigurationResult{}, errors.New("managed clients cannot declare configuration")
	}
	var request protocol.SyncConfiguration
	if err := protocol.DecodePayload(envelope, &request); err != nil {
		return protocol.SyncConfigurationResult{}, err
	}
	if len(request.Proxies) == 0 && len(request.Forwards) == 0 {
		return protocol.SyncConfigurationResult{}, errors.New("complete configuration must not be empty")
	}
	cachedResult, synchronizationError := s.checkConfigurationSync(
		session.clientID,
		session.sessionID,
		envelope.RequestID,
		request,
	)
	if synchronizationError != nil {
		s.logConfigurationSyncRejected(session, request.Revision, synchronizationError)
		if err := writeConfigurationRejection(
			session.writer,
			envelope.RequestID,
			request.Revision,
			synchronizationError,
		); err != nil {
			return protocol.SyncConfigurationResult{}, err
		}
		return protocol.SyncConfigurationResult{}, errProxyRegistrationRejected
	}
	if cachedResult != nil {
		s.logConfigurationSyncApplied(session, request, *cachedResult, true)
		return *cachedResult, nil
	}
	if rejection := validateConfigurationCapabilities(
		request,
		session.capabilities,
	); rejection != nil {
		s.logConfigurationSyncRejected(session, request.Revision, rejection.Error)
		if err := session.writer.WriteResponse(
			protocol.MessageSyncConfigurationResult,
			envelope.RequestID,
			*rejection,
		); err != nil {
			return protocol.SyncConfigurationResult{}, err
		}
		return protocol.SyncConfigurationResult{}, errProxyRegistrationRejected
	}
	proxyRequest := proxyregistry.SyncRequest{
		Revision: request.Revision,
		Proxies:  request.Proxies,
	}
	if session.mode == authentication.ModeGoverned {
		if result := s.validateGovernedProxies(session.clientID, proxyRequest); result != nil {
			rejection := configurationProxyError(result.Error)
			s.logConfigurationSyncRejected(session, request.Revision, rejection)
			if err := writeConfigurationRejection(
				session.writer,
				envelope.RequestID,
				request.Revision,
				rejection,
			); err != nil {
				return protocol.SyncConfigurationResult{}, err
			}
			return protocol.SyncConfigurationResult{}, errProxyRegistrationRejected
		}
	}
	if s.forwardRegistry == nil {
		return protocol.SyncConfigurationResult{}, errors.New("Forward Registry is unavailable")
	}
	maxActiveForwardLinks := 0
	if session.mode == authentication.ModeGoverned {
		governed, _ := s.configuration.governedClient(session.clientID)
		maxActiveForwardLinks = governed.Permissions.Forwards.Limits.MaxActiveLinks
	}
	forwardTransaction, forwardError := s.forwardRegistry.BeginSync(
		session.clientID,
		session.sessionID,
		session.writer,
		session.authentication,
		maxActiveForwardLinks,
		request.Forwards,
	)
	if forwardError != nil {
		rejection := configurationForwardError(forwardError)
		s.logConfigurationSyncRejected(session, request.Revision, rejection)
		if err := writeConfigurationRejection(
			session.writer,
			envelope.RequestID,
			request.Revision,
			rejection,
		); err != nil {
			return protocol.SyncConfigurationResult{}, err
		}
		return protocol.SyncConfigurationResult{}, errProxyRegistrationRejected
	}
	proxyResult := s.proxyRegistry.SyncAllowEmpty(
		session.clientID,
		session.sessionID,
		envelope.RequestID,
		proxyRequest,
	)
	if proxyResult.Status == proxyregistry.SyncStatusRejected {
		forwardTransaction.Rollback()
		rejection := configurationProxyError(proxyResult.Error)
		s.logConfigurationSyncRejected(session, request.Revision, rejection)
		if err := writeConfigurationRejection(
			session.writer,
			envelope.RequestID,
			request.Revision,
			rejection,
		); err != nil {
			return protocol.SyncConfigurationResult{}, err
		}
		return protocol.SyncConfigurationResult{}, errProxyRegistrationRejected
	}
	result := protocol.SyncConfigurationResult{
		Revision: request.Revision,
		Status:   protocol.ConfigurationSyncStatusApplied,
		Proxies:  proxyResult.Proxies,
		Forwards: append([]protocol.ForwardResult(nil), forwardTransaction.Results()...),
	}
	if !forwardTransaction.Commit() {
		return protocol.SyncConfigurationResult{}, errors.New("Forward generation changed while synchronizing")
	}
	s.cacheConfigurationSync(session.clientID, session.sessionID, envelope.RequestID, request, result)
	s.logConfigurationSyncApplied(session, request, result, false)
	return result, nil
}

func (s *Service) logConfigurationSyncRejected(
	session configurationSyncSession,
	revision uint64,
	rejection *protocol.ConfigurationError,
) {
	if s.logger == nil || rejection == nil {
		return
	}
	s.logger.WithComponent("proxy_registry").WarnWithFields(
		"client configuration synchronization rejected",
		nil,
		map[string]any{
			"event":         "configuration_sync_rejected",
			"client_id":     session.clientID,
			"session_id":    session.sessionID,
			"result":        "rejected",
			"revision":      revision,
			"resource_kind": rejection.ResourceKind,
			"resource_name": rejection.ResourceName,
			"error_code":    rejection.Code,
			"retryable":     rejection.Retryable,
		},
	)
}

func (s *Service) logConfigurationSyncApplied(
	session configurationSyncSession,
	request protocol.SyncConfiguration,
	result protocol.SyncConfigurationResult,
	replayed bool,
) {
	if s.logger == nil {
		return
	}
	proxyCounts := map[protocol.ProxyType]int{}
	for _, declaration := range request.Proxies {
		proxyCounts[declaration.Type]++
	}
	forwardCounts := map[protocol.ForwardType]int{}
	for _, declaration := range request.Forwards {
		forwardCounts[declaration.Type]++
	}
	s.logger.WithComponent("proxy_registry").InfoWithFields(
		"client configuration synchronized",
		map[string]any{
			"event":        "configuration_sync_applied",
			"client_id":    session.clientID,
			"session_id":   session.sessionID,
			"result":       result.Status,
			"revision":     result.Revision,
			"replayed":     replayed,
			"tcp_proxies":  proxyCounts[protocol.ProxyTypeTCP],
			"udp_proxies":  proxyCounts[protocol.ProxyTypeUDP],
			"http_proxies": proxyCounts[protocol.ProxyTypeHTTP],
			"tcp_forwards": forwardCounts[protocol.ForwardTypeTCP],
			"udp_forwards": forwardCounts[protocol.ForwardTypeUDP],
		},
	)
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
