package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/session"
	"github.com/acexy/portway/internal/transport"
)

type clientConnectionContextError struct {
	cause  error
	fields map[string]any
}

func (connectionError *clientConnectionContextError) Error() string {
	return connectionError.cause.Error()
}

func (connectionError *clientConnectionContextError) Unwrap() error {
	return connectionError.cause
}

func withClientConnectionContext(err error, fields map[string]any) error {
	if err == nil {
		return nil
	}
	return &clientConnectionContextError{cause: err, fields: fields}
}

func clientConnectionLogFields(inbound transport.Inbound, err error) map[string]any {
	fields := map[string]any{
		"connection_role": connectionRoleName(inbound.Role),
		"remote_address": inbound.RemoteAddress,
	}
	var connectionError *clientConnectionContextError
	if errors.As(err, &connectionError) {
		for name, value := range connectionError.fields {
			fields[name] = value
		}
	}
	return fields
}

func connectionRoleName(role protocol.Role) string {
	switch role {
	case protocol.RoleControl:
		return "control"
	case protocol.RoleData:
		return "data"
	default:
		return "unknown"
	}
}

func (s *Service) monitorClients(ctx context.Context) {
	ticker := time.NewTicker(clientMonitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			suspendedClients, expiredClients := s.clientRegistry.Sweep(
				now,
				controlHeartbeatTimeout,
				clientRecoveryWindow,
			)
			for _, suspended := range suspendedClients {
				if !s.suspendClient(suspended) {
					continue
				}
				s.logger.WithComponent("session").WithFields(map[string]any{
					"event":      "client_suspended",
					"client_id":  suspended.ClientID,
					"session_id": suspended.SessionID,
				}).Info("client suspended")
			}
			for _, expired := range expiredClients {
				s.proxyRegistry.Remove(expired.ClientID, expired.SessionID)
				if expired.Connection != nil {
					expired.Connection.Close()
				}
				s.logger.WithComponent("session").WithFields(map[string]any{
					"event":      "client_expired",
					"client_id":  expired.ClientID,
					"session_id": expired.SessionID,
				}).Info("client expired")
			}
		}
	}
}

func (s *Service) suspendClient(client session.Client) bool {
	s.proxyRegistry.Suspend(client.ClientID, client.SessionID)
	if s.clientRegistry.Active(client.ClientID, client.SessionID) {
		s.proxyRegistry.Activate(client.ClientID, client.SessionID)
		return false
	}
	return true
}

func (s *Service) handleDataConnection(
	ctx context.Context,
	inbound transport.Inbound,
	releaseAdmission func(),
) error {
	connection := inbound.Stream
	if err := connection.SetDeadline(time.Now().Add(dataBindTimeout)); err != nil {
		return fmt.Errorf("set TCP data bind deadline: %w", err)
	}
	envelope, err := protocol.ReadControl(connection)
	if err != nil {
		return err
	}
	s.authenticationBarrier.RLock()
	if !s.authenticationStore.IsCurrent(inbound.Authentication) {
		s.authenticationBarrier.RUnlock()
		return transport.ErrAuthentication
	}
	s.authenticationBarrier.RUnlock()
	if envelope.Type == protocol.MessageBindVNetChannel {
		if inbound.Authentication.Mode != authentication.ModeManaged || s.vnetRuntime == nil {
			return transport.ErrAuthentication
		}
		var binding protocol.BindVNetChannel
		if err := protocol.DecodePayload(envelope, &binding); err != nil {
			return err
		}
		if binding.ClientID != inbound.Authentication.ClientID {
			return transport.ErrAuthentication
		}
		return withClientConnectionContext(
			s.vnetRuntime.bind(ctx, inbound, binding, releaseAdmission),
			map[string]any{
				"client_id":       binding.ClientID,
				"session_id":      binding.SessionID,
				"pool_generation": binding.PoolGeneration,
				"channel_index":   binding.ChannelIndex,
				"channel_count":   binding.ChannelCount,
			},
		)
	}
	if envelope.Type != protocol.MessageBindLink {
		return fmt.Errorf(
			"expected %s or %s, got %s",
			protocol.MessageBindLink,
			protocol.MessageBindVNetChannel,
			envelope.Type,
		)
	}
	var binding protocol.BindLink
	if err := protocol.DecodePayload(envelope, &binding); err != nil {
		return err
	}
	if inbound.Authentication.Mode != authentication.ModeShared &&
		binding.ClientID != inbound.Authentication.ClientID {
		return transport.ErrAuthentication
	}
	return withClientConnectionContext(
		s.linkBroker.BindWithActivation(
			ctx,
			connection,
			binding,
			inbound.Authentication,
			releaseAdmission,
		),
		map[string]any{
			"client_id":  binding.ClientID,
			"session_id": binding.SessionID,
			"link_id":    binding.LinkID,
			"proxy_type": binding.ProxyType,
			"direction":  binding.Direction,
		},
	)
}

func writeSessionError(connection net.Conn, sessionError protocol.SessionError) error {
	return protocol.WriteControl(connection, protocol.MessageSessionError, sessionError)
}
