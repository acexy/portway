package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/session"
	"github.com/acexy/portway/internal/transport"
)

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
	if envelope.Type != protocol.MessageBindLink {
		return fmt.Errorf("expected %s, got %s", protocol.MessageBindLink, envelope.Type)
	}
	var binding protocol.BindLink
	if err := protocol.DecodePayload(envelope, &binding); err != nil {
		return err
	}
	if inbound.Authentication.Mode != authentication.ModeShared &&
		binding.ClientID != inbound.Authentication.ClientID {
		return transport.ErrAuthentication
	}
	s.authenticationBarrier.RLock()
	if !s.authenticationStore.IsCurrent(inbound.Authentication) {
		s.authenticationBarrier.RUnlock()
		return transport.ErrAuthentication
	}
	s.authenticationBarrier.RUnlock()
	return s.linkBroker.BindWithActivation(
		ctx,
		connection,
		binding,
		inbound.Authentication,
		releaseAdmission,
	)
}

func writeSessionError(connection net.Conn, sessionError protocol.SessionError) error {
	return protocol.WriteControl(connection, protocol.MessageSessionError, sessionError)
}
