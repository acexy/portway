package client

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

func (s *Service) syncProxies(
	connection net.Conn,
	writer *control.Writer,
) error {
	requestID, err := newRequestID()
	if err != nil {
		return err
	}
	proxies := s.runtimeProxySnapshot()
	declarations := coll.SliceCollect(proxies, func(proxyConfiguration config.ProxyConfig) protocol.ProxyDeclaration {
		return protocol.ProxyDeclaration{
			Name:       proxyConfiguration.Name,
			Type:       proxyConfiguration.Type,
			RemotePort: proxyConfiguration.Public.Port,
			Domain:     proxyConfiguration.Public.Domain,
			PublicSchemes: append(
				[]protocol.HTTPPublicScheme(nil),
				proxyConfiguration.Public.Schemes...,
			),
		}
	})
	if declarations == nil {
		declarations = []protocol.ProxyDeclaration{}
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
	s.logger.WithComponent("proxy_registry").InfoWithFields(
		"proxy registration applied",
		map[string]any{
			"event":       "proxy_registration_applied",
			"revision":    result.Revision,
			"proxy_count": len(s.configuration.Proxies),
		},
	)
	return nil
}
func newRequestID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
