package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// HTTPConfig configures the public HTTP server and its bounded resources.
type HTTPConfig struct {
	ReadHeaderTimeout              time.Duration `yaml:"read_header_timeout"`
	GracefulShutdownTimeout        time.Duration `yaml:"graceful_shutdown_timeout"`
	IdleConnectionTimeout          time.Duration `yaml:"idle_connection_timeout"`
	ResponseHeaderTimeout          time.Duration `yaml:"response_header_timeout"`
	MaxHeaderBytes                 int           `yaml:"max_header_bytes"`
	MaxConcurrentRequests          int           `yaml:"max_concurrent_requests"`
	MaxConcurrentRequestsPerClient int           `yaml:"max_concurrent_requests_per_client"`
	MaxConcurrentRequestsPerDomain int           `yaml:"max_concurrent_requests_per_domain"`
	MaxIdleConnections             int           `yaml:"max_idle_connections"`
	MaxIdleConnectionsPerDomain    int           `yaml:"max_idle_connections_per_domain"`
	MaxUpgradeConnections          int           `yaml:"max_upgrade_connections"`
	MaxUpgradeConnectionsPerClient int           `yaml:"max_upgrade_connections_per_client"`
	MaxUpgradeConnectionsPerDomain int           `yaml:"max_upgrade_connections_per_domain"`
	MaxConcurrentHTTP2Streams      int           `yaml:"max_concurrent_http2_streams"`
}

func validateHTTPConfig(configuration HTTPConfig) error {
	if configuration.ReadHeaderTimeout <= 0 ||
		configuration.ReadHeaderTimeout > httpHardMaxReadHeaderTimeout {
		return fmt.Errorf("http.read_header_timeout must be greater than zero and at most %s", httpHardMaxReadHeaderTimeout)
	}
	if configuration.GracefulShutdownTimeout <= 0 ||
		configuration.GracefulShutdownTimeout > httpHardMaxGracefulShutdownTimeout {
		return fmt.Errorf("http.graceful_shutdown_timeout must be greater than zero and at most %s", httpHardMaxGracefulShutdownTimeout)
	}
	for name, value := range map[string]time.Duration{
		"idle_connection_timeout": configuration.IdleConnectionTimeout,
		"response_header_timeout": configuration.ResponseHeaderTimeout,
	} {
		if value < 0 || value > httpHardMaxBusinessTimeout {
			return fmt.Errorf("http.%s must be zero or at most %s", name, httpHardMaxBusinessTimeout)
		}
	}
	limits := []struct {
		name  string
		value int
		max   int
	}{
		{"max_header_bytes", configuration.MaxHeaderBytes, httpHardMaxHeaderBytes},
		{"max_concurrent_requests", configuration.MaxConcurrentRequests, httpHardMaxConcurrentRequests},
		{"max_concurrent_requests_per_client", configuration.MaxConcurrentRequestsPerClient, httpHardMaxConcurrentRequestsPerClient},
		{"max_concurrent_requests_per_domain", configuration.MaxConcurrentRequestsPerDomain, httpHardMaxConcurrentRequestsPerDomain},
		{"max_idle_connections", configuration.MaxIdleConnections, httpHardMaxIdleConnections},
		{"max_idle_connections_per_domain", configuration.MaxIdleConnectionsPerDomain, httpHardMaxIdleConnectionsPerDomain},
		{"max_upgrade_connections", configuration.MaxUpgradeConnections, httpHardMaxUpgradeConnections},
		{"max_upgrade_connections_per_client", configuration.MaxUpgradeConnectionsPerClient, httpHardMaxUpgradeConnectionsPerClient},
		{"max_upgrade_connections_per_domain", configuration.MaxUpgradeConnectionsPerDomain, httpHardMaxUpgradeConnectionsPerDomain},
		{"max_concurrent_http2_streams", configuration.MaxConcurrentHTTP2Streams, httpHardMaxConcurrentHTTP2Streams},
	}
	for _, limit := range limits {
		if limit.value <= 0 || limit.value > limit.max {
			return fmt.Errorf("http.%s must be greater than zero and at most %d", limit.name, limit.max)
		}
	}
	if configuration.MaxConcurrentRequestsPerClient > configuration.MaxConcurrentRequests ||
		configuration.MaxConcurrentRequestsPerDomain > configuration.MaxConcurrentRequests ||
		configuration.MaxIdleConnectionsPerDomain > configuration.MaxIdleConnections ||
		configuration.MaxUpgradeConnectionsPerClient > configuration.MaxUpgradeConnections ||
		configuration.MaxUpgradeConnectionsPerDomain > configuration.MaxUpgradeConnections {
		return errors.New("HTTP per-client and per-domain limits must not exceed their global limits")
	}
	return nil
}

// ValidateHTTPDomain validates a canonical HTTP proxy domain.
func ValidateHTTPDomain(domain string) error {
	if domain == "" || len(domain) > 253 || domain != strings.ToLower(domain) ||
		strings.HasSuffix(domain, ".") || net.ParseIP(domain) != nil ||
		strings.ContainsAny(domain, ":/*") {
		return errors.New("must be a canonical lowercase ASCII DNS name without port, path, wildcard, or trailing dot")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("contains an invalid DNS label")
		}
		for _, character := range label {
			if character > 127 ||
				!((character >= 'a' && character <= 'z') ||
					(character >= '0' && character <= '9') ||
					character == '-') {
				return errors.New("contains an invalid DNS label")
			}
		}
	}
	return nil
}
