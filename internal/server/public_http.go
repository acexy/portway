package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/security/ipfilter"
)

// newPublicHTTPServer supplies the common public HTTP limits and request context.
// The caller configures protocols and TLS explicitly before starting Serve.
func newPublicHTTPServer(ctx context.Context, configuration config.HTTPConfig, handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: configuration.ReadHeaderTimeout,
		IdleTimeout:       configuration.PublicIdleTimeout,
		MaxHeaderBytes:    configuration.MaxHeaderBytes,
		ConnContext:       ipfilter.HTTPConnectionContext,
		BaseContext:       publicHTTPBaseContext(ctx),
	}
}

// servePublicHTTP runs in the process-owned WaitGroup. Listener failure stops
// the transport accept loop after making the original failure available to Run.
func (s *Service) servePublicHTTP(server *http.Server, listener net.Listener, listenerErrors chan<- error) {
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		listenerErrors <- err
		s.transportServer.Close()
	}
}

func shutdownPublicHTTP(server *http.Server, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = server.Shutdown(ctx)
}
