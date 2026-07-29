package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadServerParsesHTTPSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	content := []byte(`
log_level: info
transport:
  type: tcp
  listen_address: 127.0.0.1:7000
tunnel:
  bind_ip: 127.0.0.1
  http_listen_address: 127.0.0.1:8080
http:
  read_header_timeout: 12s
  graceful_shutdown_timeout: 40s
  idle_connection_timeout: 0s
  response_header_timeout: 45s
  max_header_bytes: 32768
  max_concurrent_requests: 1000
  max_concurrent_requests_per_client: 200
  max_concurrent_requests_per_domain: 100
  max_idle_connections: 300
  max_idle_connections_per_domain: 20
  max_upgrade_connections: 200
  max_upgrade_connections_per_client: 40
  max_upgrade_connections_per_domain: 20
  max_concurrent_http2_streams: 64
authentication:
  token: test-token-with-at-least-32-random-bytes
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	configuration, err := LoadServer(path, false)
	if err != nil {
		t.Fatalf("load HTTP server settings: %v", err)
	}
	if configuration.HTTP.ReadHeaderTimeout != 12*time.Second ||
		configuration.HTTP.ResponseHeaderTimeout != 45*time.Second ||
		configuration.HTTP.MaxConcurrentHTTP2Streams != 64 ||
		configuration.Tunnel.BindIP != "127.0.0.1" ||
		configuration.Tunnel.HTTPListenAddress != "127.0.0.1:8080" {
		t.Fatalf("unexpected HTTP settings: %+v", configuration.HTTP)
	}
}

func TestValidateClientAcceptsHTTPProxy(t *testing.T) {
	configuration := validHTTPClientConfiguration()
	if err := validateClient(configuration); err != nil {
		t.Fatalf("valid HTTP proxy was rejected: %v", err)
	}
}

func TestValidateClientRejectsNonCanonicalHTTPDomain(t *testing.T) {
	invalidDomains := []string{
		"App.Example.com",
		"app.example.com:8080",
		"http://app.example.com",
		"app.example.com.",
		"*.example.com",
		"127.0.0.1",
		"example..com",
	}
	for _, domain := range invalidDomains {
		t.Run(domain, func(t *testing.T) {
			configuration := validHTTPClientConfiguration()
			configuration.Proxies[0].Domain = domain
			if err := validateClient(configuration); err == nil {
				t.Fatalf("invalid HTTP domain %q was accepted", domain)
			}
		})
	}
}

func TestValidateClientUsesOneProxyNameNamespace(t *testing.T) {
	configuration := validHTTPClientConfiguration()
	configuration.Proxies = append(configuration.Proxies, ProxyConfig{
		Name: "web", Type: "tcp", LocalIP: "127.0.0.1",
		LocalPort: 22, RemotePort: 22022,
	})
	if err := validateClient(configuration); err == nil {
		t.Fatal("duplicate proxy name across HTTP and TCP was accepted")
	}
}

func TestValidateServerAcceptsDefaultHTTPSettings(t *testing.T) {
	configuration := DefaultServer()
	if configuration.Tunnel.HTTPListenAddress != "" {
		t.Fatalf(
			"default HTTP listener must be disabled, got %q",
			configuration.Tunnel.HTTPListenAddress,
		)
	}
	if err := validateServer(configuration); err != nil {
		t.Fatalf("default HTTP settings were rejected: %v", err)
	}
}

func TestValidateServerRejectsHTTPHardLimitOverflow(t *testing.T) {
	configuration := DefaultServer()
	configuration.HTTP.MaxHeaderBytes = httpHardMaxHeaderBytes + 1
	if err := validateServer(configuration); err == nil {
		t.Fatal("HTTP setting above the hard limit was accepted")
	}
}

func TestValidateServerAllowsDisabledBusinessTimeouts(t *testing.T) {
	configuration := DefaultServer()
	configuration.HTTP.IdleConnectionTimeout = 0
	configuration.HTTP.ResponseHeaderTimeout = 0
	if err := validateServer(configuration); err != nil {
		t.Fatalf("disabled HTTP business timeouts were rejected: %v", err)
	}
}

func TestValidateServerRejectsDisabledSafetyTimeout(t *testing.T) {
	configuration := DefaultServer()
	configuration.HTTP.ReadHeaderTimeout = 0
	if err := validateServer(configuration); err == nil {
		t.Fatal("disabled HTTP safety timeout was accepted")
	}
	configuration = DefaultServer()
	configuration.HTTP.GracefulShutdownTimeout = 3 * time.Minute
	if err := validateServer(configuration); err == nil {
		t.Fatal("HTTP safety timeout above the hard limit was accepted")
	}
}

func validHTTPClientConfiguration() ClientConfig {
	configuration := DefaultClient()
	configuration.ClientID = "http-client"
	configuration.Authentication.Token = "test-token-with-at-least-32-random-bytes"
	configuration.Proxies = []ProxyConfig{{
		Name: "web", Type: "http", Domain: "app.example.com",
		LocalIP: "127.0.0.1", LocalPort: 8080,
	}}
	return configuration
}
