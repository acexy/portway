package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

type managedExchange interface {
	prepare(
		context.Context,
		protocol.ManagedConfigPrepare,
		protocol.ManagedConfigStatus,
	) error
	activate(context.Context, protocol.ManagedConfigStatus) error
}

type initialManagedExchange struct {
	connection net.Conn
	writer     *control.Writer
}

func (exchange initialManagedExchange) prepare(
	_ context.Context,
	preparation protocol.ManagedConfigPrepare,
	status protocol.ManagedConfigStatus,
) error {
	if err := exchange.writer.Write(protocol.MessageManagedConfigPrepare, preparation); err != nil {
		return err
	}
	return expectManagedStatus(
		exchange.connection,
		protocol.MessageManagedConfigPrepared,
		status,
	)
}

func (exchange initialManagedExchange) activate(
	_ context.Context,
	status protocol.ManagedConfigStatus,
) error {
	if err := exchange.writer.Write(protocol.MessageManagedConfigActivate, status); err != nil {
		return err
	}
	return expectManagedStatus(
		exchange.connection,
		protocol.MessageManagedConfigApplied,
		status,
	)
}

type onlineManagedExchange struct {
	session *managedSession
}

func (s *Service) initializeManagedSession(
	ctx context.Context,
	connection net.Conn,
	clientID string,
	sessionID string,
	writer *control.Writer,
	authenticationContext authentication.Context,
) error {
	if err := connection.SetDeadline(time.Now().Add(controlHelloTimeout)); err != nil {
		return fmt.Errorf("set managed configuration deadline: %w", err)
	}
	for {
		s.authenticationBarrier.RLock()
		if !s.authenticationStore.IsCurrent(authenticationContext) {
			s.authenticationBarrier.RUnlock()
			return transport.ErrAuthentication
		}
		clientConfiguration, exists := s.configuration.managedClient(clientID)
		s.authenticationBarrier.RUnlock()
		if !exists {
			return errors.New("managed client configuration is unavailable")
		}

		// Prepare and Activate perform network I/O and must never hold the
		// authentication publication barrier.
		if err := s.applyManagedConfiguration(
			ctx,
			connection,
			clientID,
			sessionID,
			writer,
			clientConfiguration,
		); err != nil {
			return err
		}

		s.authenticationBarrier.RLock()
		latest, exists := s.configuration.managedClient(clientID)
		if !s.authenticationStore.IsCurrent(authenticationContext) {
			s.authenticationBarrier.RUnlock()
			return transport.ErrAuthentication
		}
		if !exists || !reflect.DeepEqual(latest, clientConfiguration) {
			s.authenticationBarrier.RUnlock()
			continue
		}
		if !s.clientRegistry.Activate(clientID, sessionID, time.Now()) {
			s.authenticationBarrier.RUnlock()
			return errors.New("managed client session is no longer current")
		}
		s.proxyRegistry.Activate(clientID, sessionID)
		s.registerManagedSession(clientID, sessionID, connection, writer)
		s.authenticationBarrier.RUnlock()

		if err := connection.SetDeadline(time.Time{}); err != nil {
			s.unregisterManagedSession(clientID, sessionID)
			return fmt.Errorf("clear managed configuration deadline: %w", err)
		}
		return nil
	}
}

func (exchange onlineManagedExchange) prepare(
	ctx context.Context,
	preparation protocol.ManagedConfigPrepare,
	status protocol.ManagedConfigStatus,
) error {
	drainManagedStatus(exchange.session.prepared)
	drainManagedStatus(exchange.session.applied)
	if err := exchange.session.writer.Write(
		protocol.MessageManagedConfigPrepare,
		preparation,
	); err != nil {
		return err
	}
	return waitManagedStatus(ctx, exchange.session.prepared, status)
}

func (exchange onlineManagedExchange) activate(
	ctx context.Context,
	status protocol.ManagedConfigStatus,
) error {
	if err := exchange.session.writer.Write(
		protocol.MessageManagedConfigActivate,
		status,
	); err != nil {
		return err
	}
	return waitManagedStatus(ctx, exchange.session.applied, status)
}

func (s *Service) applyManagedGeneration(
	ctx context.Context,
	clientID string,
	sessionID string,
	preparation protocol.ManagedConfigPrepare,
	declarations protocol.SyncProxies,
	exchange managedExchange,
	deactivate bool,
) error {
	status := protocol.ManagedConfigStatus{
		Revision: preparation.Revision,
		Digest:   preparation.Digest,
	}
	if err := exchange.prepare(ctx, preparation, status); err != nil {
		return err
	}
	if deactivate {
		s.proxyRegistry.Deactivate(clientID, sessionID)
	}
	result := s.proxyRegistry.Sync(
		clientID,
		sessionID,
		"managed-"+preparation.Digest,
		declarations,
	)
	if result.Status != protocol.ProxySyncStatusApplied {
		if deactivate {
			s.proxyRegistry.Activate(clientID, sessionID)
		}
		if result.Error != nil {
			return fmt.Errorf(
				"apply managed proxy configuration: %s: %s",
				result.Error.Code,
				result.Error.Message,
			)
		}
		return errors.New("apply managed proxy configuration: rejected")
	}
	if err := exchange.activate(ctx, status); err != nil {
		return err
	}
	if deactivate {
		s.proxyRegistry.Activate(clientID, sessionID)
	}
	return nil
}
