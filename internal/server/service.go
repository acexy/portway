// Package server provides the Portway server runtime.
package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/buildinfo"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	proxyregistry "github.com/acexy/portway/internal/proxy/registry"
	"github.com/acexy/portway/internal/security/ipfilter"
	"github.com/acexy/portway/internal/session"
	"github.com/acexy/portway/internal/transport"
	transportfactory "github.com/acexy/portway/internal/transport/factory"
)

var errProxyRegistrationRejected = errors.New("proxy registration rejected")

type restartRequiredError struct {
	field string
}

func (reloadError restartRequiredError) Error() string {
	return fmt.Sprintf("%s changed and requires restart", reloadError.field)
}

// Service manages the server process lifecycle.
//
// It owns the client listener, control sessions, proxy registration, and
// session-scoped TCP proxy resources.
type Service struct {
	logger                *logging.Logger
	configuration         *configurationManager
	clientRegistry        *session.Registry
	proxyRegistry         *proxyregistry.Registry
	linkBroker            *link.Broker
	transportServer       transport.Server
	authenticationStore   *authentication.Store
	authenticationBarrier sync.RWMutex
	managed               *managedCoordinator
}

// NewService creates a server service.
func NewService(logger *logging.Logger, configuration config.ServerConfig) *Service {
	if configuration.Generation == 0 {
		configuration.Generation = 1
	}
	return &Service{
		logger:         logger,
		configuration:  newConfigurationManager(configuration),
		clientRegistry: session.NewRegistry(),
		managed:        newManagedCoordinator(),
	}
}

// Run runs the server until the parent context is canceled.
func (s *Service) Run(ctx context.Context) error {
	configuration := s.configuration.snapshot()
	s.logger.InfoWithFields("server started", map[string]any{
		"event":          "server_started",
		"listen_address": configuration.Transport.ListenAddress,
	})
	defer s.logger.Info("server stopped")

	sourceFilter, err := ipfilter.New(
		ctx,
		s.logger.WithComponent("ip_filter"),
		configuration.Security.IPDenyFile,
	)
	if err != nil {
		return err
	}
	defer sourceFilter.Close()

	authenticationSnapshot, err := config.BuildAuthenticationSnapshot(configuration)
	if err != nil {
		return fmt.Errorf("build authentication snapshot: %w", err)
	}
	s.authenticationStore = authentication.NewStore(authenticationSnapshot)

	transportServer, err := transportfactory.NewServer(
		ctx,
		configuration,
		s.authenticationStore,
		maxConcurrentConnections,
		sourceFilter,
	)
	if err != nil {
		return err
	}
	s.transportServer = transportServer
	defer transportServer.Close()

	var sessions sync.WaitGroup
	defer sessions.Wait()
	sessionContext, cancelSessions := context.WithCancel(ctx)
	s.linkBroker = link.NewBroker(sessionContext)
	defer s.linkBroker.Close()
	s.proxyRegistry = proxyregistry.NewConfigured(
		sessionContext,
		s.logger.WithComponent("proxy_registry"),
		configuration.Tunnel.BindIP,
		s.linkBroker,
		configuration.Tunnel.HTTPListenAddress != "",
		configuration.HTTP,
		configuration.UDP,
		sourceFilter,
	)
	if err := s.proxyRegistry.ConfigureManagedReservations(
		configuration.ManagedClients,
	); err != nil {
		return fmt.Errorf("configure managed reservations: %w", err)
	}
	defer s.proxyRegistry.Close()
	defer cancelSessions()
	httpErrors := make(chan error, 1)
	if configuration.Tunnel.HTTPListenAddress != "" {
		httpListener, listenError := (&net.ListenConfig{}).Listen(
			ctx,
			"tcp",
			configuration.Tunnel.HTTPListenAddress,
		)
		if listenError != nil {
			return fmt.Errorf(
				"listen for HTTP proxy requests on %q: %w",
				configuration.Tunnel.HTTPListenAddress,
				listenError,
			)
		}
		if configuration.Security.HTTPClientIPHeader == "" {
			httpListener = ipfilter.WrapListenerFor(httpListener, sourceFilter, "http_socket")
		}
		httpProtocols := new(http.Protocols)
		httpProtocols.SetHTTP1(true)
		httpProtocols.SetUnencryptedHTTP2(true)
		httpServer := &http.Server{
			Handler: ipfilter.HTTPHandler(
				sourceFilter,
				configuration.Security.HTTPClientIPHeader,
				s.proxyRegistry,
			),
			ReadHeaderTimeout: configuration.HTTP.ReadHeaderTimeout,
			MaxHeaderBytes:    configuration.HTTP.MaxHeaderBytes,
			Protocols:         httpProtocols,
			ConnContext:       ipfilter.HTTPConnectionContext,
		}
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			serveError := httpServer.Serve(httpListener)
			if serveError != nil && !errors.Is(serveError, http.ErrServerClosed) {
				httpErrors <- serveError
				transportServer.Close()
			}
		}()
		defer func() {
			shutdownContext, cancel := context.WithTimeout(
				context.Background(),
				configuration.HTTP.GracefulShutdownTimeout,
			)
			defer cancel()
			_ = httpServer.Shutdown(shutdownContext)
		}()
	}
	sessions.Add(1)
	go func() {
		defer sessions.Done()
		s.monitorClients(sessionContext)
	}()
	sessions.Add(1)
	go func() {
		defer sessions.Done()
		s.watchConfiguration(sessionContext)
	}()

	for {
		inbound, err := transportServer.Accept(ctx)
		if err != nil {
			select {
			case httpError := <-httpErrors:
				return fmt.Errorf("serve HTTP proxy requests: %w", httpError)
			default:
			}
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.logger.TraceWithField(
			"client transport stream accepted",
			"remote_address",
			inbound.RemoteAddress,
		)

		sessions.Add(1)
		go func(accepted transport.Inbound) {
			defer sessions.Done()
			if err := s.handleConnection(sessionContext, accepted); err != nil &&
				!errors.Is(err, io.EOF) &&
				!errors.Is(err, net.ErrClosed) &&
				sessionContext.Err() == nil {
				s.logger.Warn("client connection ended", err)
			}
		}(inbound)
	}
}

func (s *Service) handleConnection(ctx context.Context, inbound transport.Inbound) error {
	connection := inbound.Stream
	defer connection.Close()

	stopContextClose := context.AfterFunc(ctx, func() {
		connection.Close()
	})
	defer stopContextClose()

	if inbound.Role == protocol.RoleData {
		return s.handleDataConnection(ctx, inbound)
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
	negotiatedCapabilities := negotiateCapabilities(clientHello.Capabilities)
	if err := protocol.WriteControl(connection, protocol.MessageServerHello, protocol.ServerHello{
		ClientID:       clientHello.ClientID,
		ManagementMode: string(inbound.Authentication.Mode),
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
	writer := control.NewWriter(connection)
	maxActiveLinks := 0
	if inbound.Authentication.Mode == authentication.ModeGoverned {
		governed, _ := s.configuration.governedClient(clientHello.ClientID)
		maxActiveLinks = governed.Permissions.Limits.MaxActiveLinks
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
			return
		}
		s.clientRegistry.Remove(clientHello.ClientID, sessionID)
		s.proxyRegistry.Remove(clientHello.ClientID, sessionID)
	}()

	if err := connection.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear control hello deadline: %w", err)
	}
	if inbound.Authentication.Mode == authentication.ModeManaged {
		s.authenticationBarrier.RLock()
		managedError := func() error {
			defer s.authenticationBarrier.RUnlock()
			if !s.authenticationStore.IsCurrent(inbound.Authentication) {
				return transport.ErrAuthentication
			}
			if err := connection.SetDeadline(time.Now().Add(controlHelloTimeout)); err != nil {
				return fmt.Errorf("set managed configuration deadline: %w", err)
			}
			if err := s.applyManagedConfiguration(
				ctx,
				connection,
				clientHello.ClientID,
				sessionID,
				writer,
			); err != nil {
				return err
			}
			if !s.clientRegistry.Activate(clientHello.ClientID, sessionID, time.Now()) {
				return errors.New("managed client session is no longer current")
			}
			if err := connection.SetDeadline(time.Time{}); err != nil {
				return fmt.Errorf("clear managed configuration deadline: %w", err)
			}
			s.registerManagedSession(
				clientHello.ClientID,
				sessionID,
				connection,
				writer,
			)
			return nil
		}()
		if managedError != nil {
			return managedError
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

func (s *Service) applyManagedConfiguration(
	ctx context.Context,
	connection net.Conn,
	clientID string,
	sessionID string,
	writer *control.Writer,
) error {
	clientConfiguration, exists := s.configuration.managedClient(clientID)
	if !exists {
		return errors.New("managed client configuration is unavailable")
	}
	preparation, declarations, err := managedConfigurationPayload(clientConfiguration)
	if err != nil {
		return fmt.Errorf("build managed configuration: %w", err)
	}
	return s.applyManagedGeneration(
		ctx,
		clientID,
		sessionID,
		preparation,
		declarations,
		initialManagedExchange{connection: connection, writer: writer},
		false,
	)
}

func expectManagedStatus(
	connection net.Conn,
	messageType protocol.MessageType,
	expected protocol.ManagedConfigStatus,
) error {
	envelope, err := protocol.ReadControl(connection)
	if err != nil {
		return err
	}
	if envelope.Type != messageType {
		return fmt.Errorf("expected %s, got %s", messageType, envelope.Type)
	}
	var actual protocol.ManagedConfigStatus
	if err := protocol.DecodePayload(envelope, &actual); err != nil {
		return err
	}
	if actual != expected {
		return errors.New("managed configuration status does not match")
	}
	return nil
}

func (s *Service) registerManagedSession(
	clientID string,
	sessionID string,
	connection net.Conn,
	writer *control.Writer,
) {
	s.managed.register(clientID, &managedSession{
		sessionID:  sessionID,
		connection: connection,
		writer:     writer,
		prepared:   make(chan protocol.ManagedConfigStatus, 1),
		applied:    make(chan protocol.ManagedConfigStatus, 1),
	})
}

func (s *Service) unregisterManagedSession(clientID string, sessionID string) {
	s.managed.unregister(clientID, sessionID)
}

func (s *Service) publishManagedStatus(
	clientID string,
	sessionID string,
	messageType protocol.MessageType,
	status protocol.ManagedConfigStatus,
) bool {
	return s.managed.publish(clientID, sessionID, messageType, status)
}

func managedConfigurationPayload(
	clientConfiguration config.ManagedClientConfig,
) (protocol.ManagedConfigPrepare, protocol.SyncProxies, error) {
	managedProxies := make(
		[]protocol.ManagedProxy,
		0,
		len(clientConfiguration.Configuration.Proxies),
	)
	declarations := make(
		[]protocol.ProxyDeclaration,
		0,
		len(clientConfiguration.Configuration.Proxies),
	)
	for _, proxyConfiguration := range clientConfiguration.Configuration.Proxies {
		managedProxies = append(managedProxies, protocol.ManagedProxy{
			Name:       proxyConfiguration.Name,
			Type:       protocol.ProxyType(proxyConfiguration.Type),
			LocalIP:    proxyConfiguration.LocalIP,
			LocalPort:  proxyConfiguration.LocalPort,
			RemotePort: proxyConfiguration.RemotePort,
			Domain:     proxyConfiguration.Domain,
		})
		declarations = append(declarations, protocol.ProxyDeclaration{
			Name:       proxyConfiguration.Name,
			Type:       protocol.ProxyType(proxyConfiguration.Type),
			RemotePort: proxyConfiguration.RemotePort,
			Domain:     proxyConfiguration.Domain,
		})
	}
	digest, err := protocol.ManagedConfigurationDigest(managedProxies)
	if err != nil {
		return protocol.ManagedConfigPrepare{}, protocol.SyncProxies{}, err
	}
	return protocol.ManagedConfigPrepare{
			Revision: clientConfiguration.Configuration.Revision,
			Digest:   digest,
			Proxies:  managedProxies,
		}, protocol.SyncProxies{
			Revision: clientConfiguration.Configuration.Revision,
			Proxies:  declarations,
		}, nil
}

func (s *Service) rolloutManagedConfiguration(
	ctx context.Context,
	clientID string,
	configuration config.ManagedClientConfig,
) error {
	current := s.managed.get(clientID)
	if current == nil {
		return nil
	}
	current.mutex.Lock()
	defer current.mutex.Unlock()

	preparation, declarations, err := managedConfigurationPayload(configuration)
	if err != nil {
		return fmt.Errorf("build managed rollout: %w", err)
	}
	rolloutContext, cancel := context.WithTimeout(ctx, managedRolloutTimeout)
	defer cancel()
	return s.applyManagedGeneration(
		rolloutContext,
		clientID,
		current.sessionID,
		preparation,
		declarations,
		onlineManagedExchange{session: current},
		true,
	)
}

func drainManagedStatus(statuses chan protocol.ManagedConfigStatus) {
	for {
		select {
		case <-statuses:
		default:
			return
		}
	}
}

func waitManagedStatus(
	ctx context.Context,
	statuses <-chan protocol.ManagedConfigStatus,
	expected protocol.ManagedConfigStatus,
) error {
	select {
	case actual := <-statuses:
		if actual != expected {
			return errors.New("managed configuration status does not match")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) serveControlMessages(
	connection net.Conn,
	clientID string,
	sessionID string,
	sessionLogger *logging.Logger,
	writer *control.Writer,
	negotiatedCapabilities []string,
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
					string(declaration.Type),
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

func (s *Service) handleDataConnection(ctx context.Context, inbound transport.Inbound) error {
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
	return s.linkBroker.Bind(ctx, connection, binding, inbound.Authentication)
}

func writeSessionError(connection net.Conn, sessionError protocol.SessionError) error {
	return protocol.WriteControl(connection, protocol.MessageSessionError, sessionError)
}

func negotiateCapabilities(clientCapabilities []string) []string {
	supported := map[string]struct{}{
		"tcp":          {},
		"udp":          {},
		"http":         {},
		"json-control": {},
	}
	negotiated := coll.SliceFilter(
		clientCapabilities,
		func(capability string) bool {
			_, supportedCapability := supported[capability]
			return supportedCapability
		},
	)
	if negotiated == nil {
		return []string{}
	}
	return negotiated
}

func (s *Service) validateGovernedProxies(
	clientID string,
	request protocol.SyncProxies,
) *protocol.SyncResult {
	clientConfiguration, exists := s.configuration.governedClient(clientID)
	if !exists {
		return governedRejection(
			request.Revision,
			protocol.ProxyErrorInvalidRequest,
			"",
			"governed client configuration is unavailable",
		)
	}
	permissions := clientConfiguration.Permissions
	allowedTypes := make(map[string]struct{}, len(permissions.ProxyTypes))
	for _, proxyType := range permissions.ProxyTypes {
		allowedTypes[proxyType] = struct{}{}
	}
	typeCounts := make(map[protocol.ProxyType]int)
	for _, declaration := range request.Proxies {
		if _, allowed := allowedTypes[string(declaration.Type)]; !allowed {
			return governedRejection(
				request.Revision,
				protocol.ProxyErrorProxyTypeNotAllowed,
				declaration.Name,
				"proxy type is not allowed",
			)
		}
		typeCounts[declaration.Type]++
		switch declaration.Type {
		case protocol.ProxyTypeTCP:
			if !portAllowed(declaration.RemotePort, permissions.TCP.RemotePortRanges) {
				return governedRejection(
					request.Revision,
					protocol.ProxyErrorRemotePortNotAllowed,
					declaration.Name,
					"remote TCP port is not allowed",
				)
			}
		case protocol.ProxyTypeUDP:
			if !portAllowed(declaration.RemotePort, permissions.UDP.RemotePortRanges) {
				return governedRejection(
					request.Revision,
					protocol.ProxyErrorRemotePortNotAllowed,
					declaration.Name,
					"remote UDP port is not allowed",
				)
			}
		case protocol.ProxyTypeHTTP:
			if !domainAllowed(declaration.Domain, permissions.HTTP.Domains) {
				return governedRejection(
					request.Revision,
					protocol.ProxyErrorDomainNotAllowed,
					declaration.Name,
					"HTTP domain is not allowed",
				)
			}
		}
	}
	limits := permissions.Limits
	if (limits.MaxProxies > 0 && len(request.Proxies) > limits.MaxProxies) ||
		(limits.MaxTCPProxies > 0 &&
			typeCounts[protocol.ProxyTypeTCP] > limits.MaxTCPProxies) ||
		(limits.MaxUDPProxies > 0 &&
			typeCounts[protocol.ProxyTypeUDP] > limits.MaxUDPProxies) ||
		(limits.MaxHTTPProxies > 0 &&
			typeCounts[protocol.ProxyTypeHTTP] > limits.MaxHTTPProxies) {
		return governedRejection(
			request.Revision,
			protocol.ProxyErrorClientLimitExceeded,
			"",
			"client proxy limit exceeded",
		)
	}
	return nil
}

func (s *Service) watchConfiguration(ctx context.Context) {
	sourcePath := s.configuration.snapshot().SourcePath
	if sourcePath == "" {
		return
	}
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	lastError := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		candidate, err := config.LoadServer(sourcePath, false)
		if err == nil {
			err = s.applyConfigurationCandidateContext(ctx, candidate)
		}
		if err != nil {
			if err.Error() != lastError {
				fields := map[string]any{
					"event":       "config_reload_failed",
					"error_code":  reloadErrorCode(err),
					"generation":  s.currentConfigurationGeneration(),
					"config_file": sourcePath,
				}
				var restartError restartRequiredError
				if errors.As(err, &restartError) {
					fields["field"] = restartError.field
				}
				s.logger.WithComponent("config_reload").WithFields(fields).Warn(
					"configuration reload failed; previous snapshot remains active",
					err,
				)
				lastError = err.Error()
			}
			continue
		}
		if lastError != "" {
			s.logger.WithComponent("config_reload").InfoWithFields(
				"configuration reload recovered",
				map[string]any{
					"event":       "config_reload_recovered",
					"config_file": sourcePath,
				},
			)
			lastError = ""
		}
	}
}

func (s *Service) applyConfigurationCandidate(candidate config.ServerConfig) error {
	return s.applyConfigurationCandidateContext(context.Background(), candidate)
}

func (s *Service) applyConfigurationCandidateContext(
	ctx context.Context,
	candidate config.ServerConfig,
) error {
	s.authenticationBarrier.Lock()
	barrierHeld := true
	defer func() {
		if barrierHeld {
			s.authenticationBarrier.Unlock()
		}
	}()

	current := s.configuration.snapshot()

	if candidate.Authentication.SharedToken != nil &&
		*candidate.Authentication.SharedToken == "" &&
		current.Authentication.SharedToken != nil {
		if !current.SharedTokenGenerated {
			return restartRequiredError{field: "authentication.shared_token"}
		}
		sharedToken := *current.Authentication.SharedToken
		candidate.Authentication.SharedToken = &sharedToken
		candidate.SharedTokenGenerated = true
	}
	if _, _, err := config.EnsureServerToken(&candidate); err != nil {
		return err
	}
	if !reflect.DeepEqual(candidate.Transport, current.Transport) {
		return restartRequiredError{
			field: changedYAMLField("transport", current.Transport, candidate.Transport),
		}
	}
	if !reflect.DeepEqual(candidate.Tunnel, current.Tunnel) {
		return restartRequiredError{
			field: changedYAMLField("tunnel", current.Tunnel, candidate.Tunnel),
		}
	}
	if !reflect.DeepEqual(candidate.HTTP, current.HTTP) {
		return restartRequiredError{
			field: changedYAMLField("http", current.HTTP, candidate.HTTP),
		}
	}
	if !reflect.DeepEqual(candidate.UDP, current.UDP) {
		return restartRequiredError{
			field: changedYAMLField("udp", current.UDP, candidate.UDP),
		}
	}
	if !reflect.DeepEqual(candidate.Security, current.Security) {
		return restartRequiredError{
			field: changedYAMLField("security", current.Security, candidate.Security),
		}
	}
	if err := validateManagedRevisionTransitions(current, candidate); err != nil {
		return err
	}
	if reflect.DeepEqual(candidate.Authentication, current.Authentication) &&
		reflect.DeepEqual(candidate.GovernedClients, current.GovernedClients) &&
		reflect.DeepEqual(candidate.ManagedClients, current.ManagedClients) &&
		candidate.LogLevel == current.LogLevel {
		s.configuration.updateSourceDigest(candidate.SourceDigest)
		return nil
	}
	snapshot, err := config.BuildAuthenticationSnapshot(candidate)
	if err != nil {
		return err
	}
	if candidate.LogLevel != current.LogLevel {
		if err := logging.EnableConsole(candidate.LogLevel); err != nil {
			return fmt.Errorf("apply log level: %w", err)
		}
	}
	authenticationChanged :=
		!reflect.DeepEqual(candidate.Authentication, current.Authentication) ||
			!reflect.DeepEqual(candidate.GovernedClients, current.GovernedClients) ||
			!reflect.DeepEqual(candidate.ManagedClients, current.ManagedClients)

	revokedContexts := revokedAuthenticationContexts(
		s.authenticationStore.Load(),
		snapshot,
		current,
		candidate,
	)
	managedChanges := changedManagedClients(current, candidate)
	governedAdded, governedChanged, governedRemoved := mapChangeCounts(
		current.GovernedClients,
		candidate.GovernedClients,
	)
	managedAdded, managedChanged, managedRemoved := mapChangeCounts(
		current.ManagedClients,
		candidate.ManagedClients,
	)
	if s.proxyRegistry != nil {
		if err := s.proxyRegistry.ConfigureManagedReservations(
			candidate.ManagedClients,
		); err != nil {
			if candidate.LogLevel != current.LogLevel {
				_ = logging.EnableConsole(current.LogLevel)
			}
			return fmt.Errorf("validate managed reservations: %w", err)
		}
	}
	candidate.Generation = current.Generation + 1

	s.configuration.publish(candidate)
	s.authenticationStore.ReplaceRevoking(snapshot, revokedContexts)

	var revokedSessions []session.ExpiredClient
	cleanupCallbacks := make([]func(), 0)
	if authenticationChanged {
		revokedSessions = s.clientRegistry.RevokeAuthentication(revokedContexts)
		if s.proxyRegistry != nil {
			for _, revoked := range revokedSessions {
				cleanupCallbacks = append(
					cleanupCallbacks,
					s.proxyRegistry.Detach(revoked.ClientID, revoked.SessionID),
				)
			}
		}
	}
	s.authenticationBarrier.Unlock()
	barrierHeld = false

	if s.transportServer != nil {
		s.transportServer.RevokeAuthentication(revokedContexts)
	}
	for _, cleanup := range cleanupCallbacks {
		cleanup()
	}
	for _, revoked := range revokedSessions {
		if revoked.Connection != nil {
			_ = revoked.Connection.Close()
		}
	}
	s.rolloutManagedConfigurations(ctx, managedChanges, candidate)
	s.logger.WithComponent("config_reload").InfoWithFields(
		"configuration reload applied",
		map[string]any{
			"event":                 "config_reload_applied",
			"config_file":           candidate.SourcePath,
			"governed_clients_path": candidate.Authentication.GovernedClientsPath,
			"managed_clients_path":  candidate.Authentication.ManagedClientsPath,
			"old_generation":        current.Generation,
			"new_generation":        candidate.Generation,
			"log_level_changed":     candidate.LogLevel != current.LogLevel,
			"shared_authentication_changed": !reflect.DeepEqual(
				candidate.Authentication.SharedToken,
				current.Authentication.SharedToken,
			),
			"governed_added":          governedAdded,
			"governed_changed":        governedChanged,
			"governed_removed":        governedRemoved,
			"managed_added":           managedAdded,
			"managed_changed":         managedChanged,
			"managed_removed":         managedRemoved,
			"managed_rollouts":        len(managedChanges),
			"revoked_authentications": len(revokedContexts),
			"revoked_sessions":        len(revokedSessions),
		},
	)
	return nil
}

func (s *Service) rolloutManagedConfigurations(
	ctx context.Context,
	clientIDs []string,
	candidate config.ServerConfig,
) {
	rolloutContext, cancel := context.WithTimeout(ctx, managedRolloutTimeout)
	defer cancel()
	var waitGroup sync.WaitGroup
	for _, clientID := range clientIDs {
		managed := s.managed.get(clientID)
		if managed == nil {
			continue
		}
		waitGroup.Add(1)
		go func(clientID string, managed *managedSession) {
			defer waitGroup.Done()
			if err := s.rolloutManagedConfiguration(
				rolloutContext,
				clientID,
				candidate.ManagedClients[clientID],
			); err != nil {
				_ = managed.connection.Close()
				s.logger.WithComponent("config_reload").WithFields(map[string]any{
					"event":      "managed_config_rollout_failed",
					"client_id":  clientID,
					"generation": candidate.Generation,
				}).Error("managed configuration rollout failed", err)
			}
		}(clientID, managed)
	}
	waitGroup.Wait()
}

func validateManagedRevisionTransitions(
	current config.ServerConfig,
	candidate config.ServerConfig,
) error {
	for clientID, next := range candidate.ManagedClients {
		previous, exists := current.ManagedClients[clientID]
		if !exists || previous.Token != next.Token ||
			reflect.DeepEqual(previous.Configuration, next.Configuration) {
			continue
		}
		if next.Configuration.Revision <= previous.Configuration.Revision {
			return fmt.Errorf(
				"managed client %q configuration.revision must increase from %d",
				clientID,
				previous.Configuration.Revision,
			)
		}
	}
	return nil
}

func (s *Service) currentConfigurationGeneration() uint64 {
	return s.configuration.snapshot().Generation
}

func reloadErrorCode(err error) string {
	var restartError restartRequiredError
	if errors.As(err, &restartError) {
		return "restart_required"
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "changed while loading"):
		return "configuration_generation_changed"
	case strings.Contains(message, "globally unique"):
		return "duplicate_authentication_token"
	case strings.Contains(message, "decode configuration"):
		return "invalid_yaml"
	case strings.Contains(message, "exceeds"):
		return "configuration_limit_exceeded"
	case strings.Contains(message, "authentication directory"):
		return "authentication_directory_invalid"
	default:
		return "invalid_configuration"
	}
}

func changedYAMLField(prefix string, current any, candidate any) string {
	return changedYAMLValue(prefix, reflect.ValueOf(current), reflect.ValueOf(candidate))
}

func changedYAMLValue(prefix string, current reflect.Value, candidate reflect.Value) string {
	if reflect.DeepEqual(current.Interface(), candidate.Interface()) {
		return ""
	}
	if current.Kind() != reflect.Struct {
		return prefix
	}
	valueType := current.Type()
	for index := 0; index < current.NumField(); index++ {
		if reflect.DeepEqual(current.Field(index).Interface(), candidate.Field(index).Interface()) {
			continue
		}
		name := strings.Split(valueType.Field(index).Tag.Get("yaml"), ",")[0]
		if name == "" || name == "-" {
			name = valueType.Field(index).Name
		}
		field := name
		if prefix != "" {
			field = prefix + "." + name
		}
		return changedYAMLValue(field, current.Field(index), candidate.Field(index))
	}
	return prefix
}

func revokedAuthenticationContexts(
	currentSnapshot *authentication.Snapshot,
	candidateSnapshot *authentication.Snapshot,
	current config.ServerConfig,
	candidate config.ServerConfig,
) []authentication.Context {
	contexts := currentSnapshot.Contexts()
	revoked := make([]authentication.Context, 0, len(contexts))
	for _, context := range contexts {
		if !candidateSnapshot.ContainsRecord(context) {
			revoked = append(revoked, context)
			continue
		}
		switch context.Mode {
		case authentication.ModeGoverned:
			if !reflect.DeepEqual(
				current.GovernedClients[context.ClientID],
				candidate.GovernedClients[context.ClientID],
			) {
				revoked = append(revoked, context)
			}
		case authentication.ModeManaged:
			// Managed configuration changes use the online rollout state
			// machine. Token, identity, or mode changes are handled above by
			// ContainsRecord and still revoke the old authentication record.
		}
	}
	return revoked
}

func changedManagedClients(
	current config.ServerConfig,
	candidate config.ServerConfig,
) []string {
	changed := make([]string, 0)
	for clientID, next := range candidate.ManagedClients {
		previous, exists := current.ManagedClients[clientID]
		if !exists || previous.Token != next.Token {
			continue
		}
		if !reflect.DeepEqual(previous.Configuration, next.Configuration) {
			changed = append(changed, clientID)
		}
	}
	sort.Strings(changed)
	return changed
}

func mapChangeCounts[T any](current map[string]T, candidate map[string]T) (
	added int,
	changed int,
	removed int,
) {
	for key, next := range candidate {
		previous, exists := current[key]
		if !exists {
			added++
			continue
		}
		if !reflect.DeepEqual(previous, next) {
			changed++
		}
	}
	for key := range current {
		if _, exists := candidate[key]; !exists {
			removed++
		}
	}
	return added, changed, removed
}

func portAllowed(port uint16, ranges []config.PortRange) bool {
	for _, portRange := range ranges {
		if port >= portRange.Start && port <= portRange.End {
			return true
		}
	}
	return false
}

func domainAllowed(domain string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == domain {
			return true
		}
		if !strings.HasPrefix(pattern, "*.") {
			continue
		}
		suffix := strings.TrimPrefix(pattern, "*.")
		if !strings.HasSuffix(domain, "."+suffix) {
			continue
		}
		prefix := strings.TrimSuffix(domain, "."+suffix)
		if prefix != "" && !strings.Contains(prefix, ".") {
			return true
		}
	}
	return false
}

func governedRejection(
	revision uint64,
	code protocol.ProxyErrorCode,
	proxyName string,
	message string,
) *protocol.SyncResult {
	return &protocol.SyncResult{
		Revision: revision,
		Status:   protocol.ProxySyncStatusRejected,
		Proxies:  []protocol.ProxyResult{},
		Error: &protocol.ProxyError{
			Code:      code,
			Message:   message,
			ProxyName: proxyName,
			Retryable: false,
		},
	}
}

func newSessionID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
