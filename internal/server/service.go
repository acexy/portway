// Package server provides the Portway server runtime.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	forwardregistry "github.com/acexy/portway/internal/forward/registry"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/logging"
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
	forwardRegistry       *forwardregistry.Registry
	linkBroker            *link.Broker
	transportServer       transport.Server
	authenticationStore   *authentication.Store
	authenticationBarrier sync.RWMutex
	managed               *managedCoordinator
	httpsCertificates     *httpsCertificateManager
	inboundAdmission      chan struct{}
	ready                 atomic.Bool
}

// NewService creates a server service.
func NewService(logger *logging.Logger, configuration config.ServerConfig) *Service {
	if configuration.Generation == 0 {
		configuration.Generation = 1
	}
	return &Service{
		logger:         logger,
		configuration:  newConfigurationManager(configuration),
		clientRegistry: session.NewRegistryWithLimit(maxClientSessions),
		managed:        newManagedCoordinator(),
		inboundAdmission: make(
			chan struct{},
			maxUnaffiliatedInboundConnections,
		),
	}
}

// Run runs the server until the parent context is canceled.
func (s *Service) Run(ctx context.Context) error {
	configuration := s.configuration.snapshot()
	s.logger.InfoWithFields("server started", map[string]any{
		"event":                "server_started",
		"listen_address":       configuration.Transport.ListenAddress,
		"http_listen_address":  configuration.Proxies.HTTP.ListenAddress,
		"https_listen_address": configuration.Proxies.HTTPS.ListenAddress,
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
	s.forwardRegistry = forwardregistry.New(s.linkBroker, s.forwardPolicy)
	defer s.forwardRegistry.Close()
	s.proxyRegistry = proxyregistry.NewConfigured(
		sessionContext,
		s.logger.WithComponent("proxy_registry"),
		configuration.Proxies.BindIP,
		s.linkBroker,
		configuration.Proxies.HTTP.ListenAddress != "",
		configuration.Proxies.HTTPS.ListenAddress != "",
		configuration.Proxies.HTTP.HTTPConfig,
		configuration.Proxies.UDP,
		sourceFilter,
	)
	if err := s.proxyRegistry.ConfigureManagedReservations(
		configuration.ManagedClients,
	); err != nil {
		return fmt.Errorf("configure managed reservations: %w", err)
	}
	defer s.proxyRegistry.Close()
	defer cancelSessions()
	listenerErrors := make(chan error, 3)
	if configuration.Proxies.HTTP.ListenAddress != "" {
		httpListener, listenError := (&net.ListenConfig{}).Listen(
			ctx,
			"tcp",
			configuration.Proxies.HTTP.ListenAddress,
		)
		if listenError != nil {
			return fmt.Errorf(
				"listen for HTTP proxy requests on %q: %w",
				configuration.Proxies.HTTP.ListenAddress,
				listenError,
			)
		}
		if configuration.Security.HTTPClientIPHeader == "" {
			httpListener = ipfilter.WrapListenerFor(httpListener, sourceFilter, "http_socket")
		}
		s.logger.WithComponent("proxy_http").InfoWithFields(
			"public HTTP listener started",
			map[string]any{
				"event":          "http_listener_started",
				"listen_address": configuration.Proxies.HTTP.ListenAddress,
			},
		)
		httpProtocols := new(http.Protocols)
		httpProtocols.SetHTTP1(true)
		httpProtocols.SetUnencryptedHTTP2(true)
		httpServer := &http.Server{
			Handler: ipfilter.HTTPHandler(
				sourceFilter,
				configuration.Security.HTTPClientIPHeader,
				s.proxyRegistry,
				"http_header",
			),
			ReadHeaderTimeout: configuration.Proxies.HTTP.HTTPConfig.ReadHeaderTimeout,
			IdleTimeout:       configuration.Proxies.HTTP.HTTPConfig.PublicIdleTimeout,
			MaxHeaderBytes:    configuration.Proxies.HTTP.HTTPConfig.MaxHeaderBytes,
			Protocols:         httpProtocols,
			ConnContext:       ipfilter.HTTPConnectionContext,
		}
		sessions.Go(func() {
			serveError := httpServer.Serve(httpListener)
			if serveError != nil && !errors.Is(serveError, http.ErrServerClosed) {
				listenerErrors <- serveError
				transportServer.Close()
			}
		})
		defer func() {
			shutdownContext, cancel := context.WithTimeout(
				context.Background(),
				configuration.Proxies.HTTP.HTTPConfig.GracefulShutdownTimeout,
			)
			defer cancel()
			_ = httpServer.Shutdown(shutdownContext)
		}()
	}
	if configuration.Proxies.HTTPS.ListenAddress != "" {
		s.httpsCertificates, err = newHTTPSCertificateManager(
			s.logger.WithComponent("https_certificate"),
			configuration.Proxies.HTTPS,
		)
		if err != nil {
			return fmt.Errorf("initialize HTTPS certificate: %w", err)
		}
		httpsListener, listenError := (&net.ListenConfig{}).Listen(
			ctx,
			"tcp",
			configuration.Proxies.HTTPS.ListenAddress,
		)
		if listenError != nil {
			return fmt.Errorf(
				"listen for HTTPS proxy requests on %q: %w",
				configuration.Proxies.HTTPS.ListenAddress,
				listenError,
			)
		}
		if configuration.Security.HTTPClientIPHeader == "" {
			httpsListener = ipfilter.WrapListenerFor(
				httpsListener,
				sourceFilter,
				"https_socket",
			)
		}
		s.logger.WithComponent("proxy_http").InfoWithFields(
			"public HTTPS listener started",
			map[string]any{
				"event":          "https_listener_started",
				"listen_address": configuration.Proxies.HTTPS.ListenAddress,
			},
		)
		tlsConfiguration := &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: s.httpsCertificates.getCertificate,
			NextProtos:     []string{"h2", "http/1.1"},
		}
		httpsProtocols := new(http.Protocols)
		httpsProtocols.SetHTTP1(true)
		httpsProtocols.SetHTTP2(true)
		httpsServer := &http.Server{
			Handler: ipfilter.HTTPHandler(
				sourceFilter,
				configuration.Security.HTTPClientIPHeader,
				s.proxyRegistry,
				"https_header",
			),
			ReadHeaderTimeout: configuration.Proxies.HTTP.HTTPConfig.ReadHeaderTimeout,
			IdleTimeout:       configuration.Proxies.HTTP.HTTPConfig.PublicIdleTimeout,
			MaxHeaderBytes:    configuration.Proxies.HTTP.HTTPConfig.MaxHeaderBytes,
			Protocols:         httpsProtocols,
			ConnContext:       ipfilter.HTTPConnectionContext,
			TLSConfig:         tlsConfiguration,
		}
		sessions.Go(func() {
			serveError := httpsServer.Serve(tls.NewListener(httpsListener, tlsConfiguration))
			if serveError != nil && !errors.Is(serveError, http.ErrServerClosed) {
				listenerErrors <- serveError
				transportServer.Close()
			}
		})
		defer func() {
			shutdownContext, cancel := context.WithTimeout(
				context.Background(),
				configuration.Proxies.HTTP.HTTPConfig.GracefulShutdownTimeout,
			)
			defer cancel()
			_ = httpsServer.Shutdown(shutdownContext)
		}()
		sessions.Go(func() {
			s.watchHTTPSCertificate(sessionContext)
		})
	}
	sessions.Go(func() {
		s.monitorClients(sessionContext)
	})
	sessions.Go(func() {
		s.watchConfiguration(sessionContext)
	})
	if configuration.Operations.ListenAddress != "" {
		operationsListener, listenError := (&net.ListenConfig{}).Listen(
			ctx,
			"tcp",
			configuration.Operations.ListenAddress,
		)
		if listenError != nil {
			return fmt.Errorf(
				"listen for operations requests on %q: %w",
				configuration.Operations.ListenAddress,
				listenError,
			)
		}
		operationsServer := &http.Server{
			Handler:           s.operationsHandler(),
			ReadHeaderTimeout: operationsReadHeaderTimeout,
			MaxHeaderBytes:    operationsMaxHeaderBytes,
		}
		sessions.Go(func() {
			serveError := operationsServer.Serve(operationsListener)
			if serveError != nil && !errors.Is(serveError, http.ErrServerClosed) {
				listenerErrors <- serveError
				transportServer.Close()
			}
		})
		defer func() {
			shutdownContext, cancel := context.WithTimeout(
				context.Background(),
				operationsShutdownTimeout,
			)
			defer cancel()
			_ = operationsServer.Shutdown(shutdownContext)
		}()
	}
	s.ready.Store(true)
	defer s.ready.Store(false)

	for {
		inbound, err := transportServer.Accept(ctx)
		if err != nil {
			select {
			case listenerError := <-listenerErrors:
				return fmt.Errorf("serve auxiliary listener: %w", listenerError)
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
		releaseAdmission, admitted := s.acquireInboundAdmission()
		if !admitted {
			_ = inbound.Stream.Close()
			continue
		}

		sessions.Go(func() {
			defer releaseAdmission()
			if err := s.handleAdmittedConnection(
				sessionContext,
				inbound,
				releaseAdmission,
			); err != nil &&
				!errors.Is(err, io.EOF) &&
				!errors.Is(err, net.ErrClosed) &&
				sessionContext.Err() == nil {
				s.logger.Warn("client connection ended", err)
			}
		})
	}
}

func (s *Service) acquireInboundAdmission() (func(), bool) {
	select {
	case s.inboundAdmission <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-s.inboundAdmission })
		}, true
	default:
		return func() {}, false
	}
}
