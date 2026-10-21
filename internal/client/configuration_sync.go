package client

import (
	"fmt"
	"net"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

func (s *Service) syncConfiguration(
	connection net.Conn,
	writer *control.Writer,
) (protocol.SyncConfigurationResult, error) {
	requestID, err := newRequestID()
	if err != nil {
		return protocol.SyncConfigurationResult{}, err
	}
	proxies := coll.SliceCollect(s.runtimeProxySnapshot(), config.ProxyDeclaration)
	forwards := coll.SliceCollect(s.runtimeForwardSnapshot(), config.ForwardDeclaration)
	if proxies == nil {
		proxies = []protocol.ProxyDeclaration{}
	}
	if forwards == nil {
		forwards = []protocol.ForwardDeclaration{}
	}
	if err := writer.WriteRequest(
		protocol.MessageSyncConfiguration,
		requestID,
		protocol.SyncConfiguration{Revision: 1, Proxies: proxies, Forwards: forwards},
	); err != nil {
		return protocol.SyncConfigurationResult{}, err
	}
	envelope, err := protocol.ReadControl(connection)
	if err != nil {
		return protocol.SyncConfigurationResult{}, classifyControlProtocolError(err)
	}
	if envelope.Type != protocol.MessageSyncConfigurationResult || envelope.RequestID != requestID {
		return protocol.SyncConfigurationResult{}, fmt.Errorf(
			"%w: expected %s response for request %q",
			transport.ErrProtocol,
			protocol.MessageSyncConfigurationResult,
			requestID,
		)
	}
	var result protocol.SyncConfigurationResult
	if err := protocol.DecodePayload(envelope, &result); err != nil {
		return protocol.SyncConfigurationResult{}, classifyControlProtocolError(err)
	}
	if result.Status != protocol.ConfigurationSyncStatusApplied {
		if result.Error == nil {
			return protocol.SyncConfigurationResult{}, fmt.Errorf(
				"%w: configuration rejected without an error",
				transport.ErrProtocol,
			)
		}
		return protocol.SyncConfigurationResult{}, &configurationRegistrationError{
			code:         result.Error.Code,
			resourceKind: result.Error.ResourceKind,
			resourceName: result.Error.ResourceName,
			message:      result.Error.Message,
			retryable:    result.Error.Retryable,
		}
	}
	return result, nil
}
