package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/acexy/portway/internal/protocol"
)

func TestLoadServerParsesHTTPSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	content := []byte(`
log_level: info
transport:
  type: tcp
  listen_address: 127.0.0.1:7000
proxies:
  bind_ip: 127.0.0.1
  http:
    listen_address: 127.0.0.1:8080
    read_header_timeout: 12s
    request_body_timeout: 2m
    public_idle_timeout: 90s
    graceful_shutdown_timeout: 40s
    idle_connection_timeout: 0s
    response_header_timeout: 45s
    upgrade_idle_timeout: 15m
    max_request_body_bytes: 1048576
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
  https:
    listen_address: 127.0.0.1:8443
    certificates:
      - domains: [app.example.com]
        cert_file: server.crt
        key_file: server.key
authentication:
  shared_token: cG9ydHdheS10ZXN0LWNsaWVudC10b2tlbi0wMDAwMDA
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	configuration, err := LoadServer(path, false)
	if err != nil {
		t.Fatalf("load HTTP server settings: %v", err)
	}
	if configuration.Proxies.HTTP.HTTPConfig.ReadHeaderTimeout != 12*time.Second ||
		configuration.Proxies.HTTP.HTTPConfig.RequestBodyTimeout != 2*time.Minute ||
		configuration.Proxies.HTTP.HTTPConfig.PublicIdleTimeout != 90*time.Second ||
		configuration.Proxies.HTTP.HTTPConfig.ResponseHeaderTimeout != 45*time.Second ||
		configuration.Proxies.HTTP.HTTPConfig.UpgradeIdleTimeout != 15*time.Minute ||
		configuration.Proxies.HTTP.HTTPConfig.MaxRequestBodyBytes != 1048576 ||
		configuration.Proxies.HTTP.HTTPConfig.MaxConcurrentHTTP2Streams != 64 ||
		configuration.Proxies.BindIP != "127.0.0.1" ||
		configuration.Proxies.HTTP.ListenAddress != "127.0.0.1:8080" ||
		configuration.Proxies.HTTPS.ListenAddress != "127.0.0.1:8443" ||
		len(configuration.Proxies.HTTPS.Certificates) != 1 ||
		configuration.Proxies.HTTPS.Certificates[0].Domains[0] != "app.example.com" ||
		configuration.Proxies.HTTPS.Certificates[0].CertFile != "server.crt" ||
		configuration.Proxies.HTTPS.Certificates[0].KeyFile != "server.key" {
		t.Fatalf("unexpected HTTP settings: %+v", configuration.Proxies.HTTP.HTTPConfig)
	}
}

func TestLoadServerRejectsLegacyProxyLayout(t *testing.T) {
	for _, legacyField := range []string{"tunnel", "http", "https", "udp"} {
		t.Run(legacyField, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.yaml")
			content := []byte(legacyField + ": {}\n")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadServer(path, false); err == nil {
				t.Fatalf("legacy top-level field %q was accepted", legacyField)
			}
		})
	}
}

func TestValidateServerRequiresHTTPSCertificatePair(t *testing.T) {
	configuration := DefaultServer()
	configuration.Proxies.HTTPS.ListenAddress = "127.0.0.1:8443"
	if err := validateServer(configuration); err == nil {
		t.Fatal("HTTPS listener without certificate pair was accepted")
	}
	configuration.Proxies.HTTPS.Certificates = []HTTPSCertificateConfig{{
		Domains:  []string{"app.example.com"},
		CertFile: "server.crt",
		KeyFile:  "server.key",
	}}
	if err := validateServer(configuration); err != nil {
		t.Fatalf("valid HTTPS configuration was rejected: %v", err)
	}
	configuration.Proxies.HTTPS.Certificates[0].KeyFile = ""
	if err := validateServer(configuration); err == nil {
		t.Fatal("HTTPS certificate without private key was accepted")
	}
}

func TestValidateServerRejectsInvalidHTTPSCertificateMappings(t *testing.T) {
	testCases := []struct {
		name         string
		certificates []HTTPSCertificateConfig
	}{
		{
			name: "empty domains",
			certificates: []HTTPSCertificateConfig{{
				CertFile: "server.crt", KeyFile: "server.key",
			}},
		},
		{
			name: "noncanonical domain",
			certificates: []HTTPSCertificateConfig{{
				Domains: []string{"App.Example.com"}, CertFile: "server.crt", KeyFile: "server.key",
			}},
		},
		{
			name: "multi-label wildcard",
			certificates: []HTTPSCertificateConfig{{
				Domains: []string{"*.*.example.com"}, CertFile: "server.crt", KeyFile: "server.key",
			}},
		},
		{
			name: "duplicate domain",
			certificates: []HTTPSCertificateConfig{
				{Domains: []string{"app.example.com"}, CertFile: "first.crt", KeyFile: "first.key"},
				{Domains: []string{"app.example.com"}, CertFile: "second.crt", KeyFile: "second.key"},
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			configuration := DefaultServer()
			configuration.Proxies.HTTPS.ListenAddress = "127.0.0.1:8443"
			configuration.Proxies.HTTPS.Certificates = testCase.certificates
			if err := validateServer(configuration); err == nil {
				t.Fatal("invalid HTTPS certificate mapping was accepted")
			}
		})
	}
}

func TestValidateServerRejectsPublicTCPListenerConflicts(t *testing.T) {
	configuration := DefaultServer()
	configuration.Proxies.HTTPS.ListenAddress = configuration.Transport.ListenAddress
	configuration.Proxies.HTTPS.Certificates = []HTTPSCertificateConfig{{
		Domains:  []string{"app.example.com"},
		CertFile: "server.crt",
		KeyFile:  "server.key",
	}}
	if err := validateServer(configuration); err == nil {
		t.Fatal("HTTPS and transport listener conflict was accepted")
	}

	configuration.Proxies.HTTPS.ListenAddress = "127.0.0.1:8080"
	configuration.Proxies.HTTP.ListenAddress = "127.0.0.1:8080"
	if err := validateServer(configuration); err == nil {
		t.Fatal("HTTP and HTTPS listener conflict was accepted")
	}
}

func TestValidateClientAcceptsHTTPProxy(t *testing.T) {
	configuration := validHTTPClientConfiguration()
	if err := validateClient(configuration); err != nil {
		t.Fatalf("valid HTTP proxy was rejected: %v", err)
	}
}

func TestValidateClientRejectsInvalidHTTPPublicSchemes(t *testing.T) {
	testCases := []struct {
		name    string
		schemes []protocol.HTTPPublicScheme
	}{
		{name: "unknown", schemes: []protocol.HTTPPublicScheme{"h3"}},
		{name: "duplicate", schemes: []protocol.HTTPPublicScheme{
			protocol.HTTPPublicSchemeHTTPS,
			protocol.HTTPPublicSchemeHTTPS,
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			configuration := validHTTPClientConfiguration()
			configuration.Proxies[0].Public.Schemes = testCase.schemes
			if err := validateClient(configuration); err == nil {
				t.Fatal("invalid HTTP public schemes were accepted")
			}
		})
	}
}

func TestValidateClientDefaultsHTTPPublicSchemes(t *testing.T) {
	configuration := validHTTPClientConfiguration()
	configuration.Proxies[0].Public.Schemes = nil
	if err := validateClient(configuration); err != nil {
		t.Fatalf("default HTTP public scheme was rejected: %v", err)
	}
	if len(configuration.Proxies[0].Public.Schemes) != 1 ||
		configuration.Proxies[0].Public.Schemes[0] != protocol.HTTPPublicSchemeHTTP {
		t.Fatalf("public schemes = %v, want [http]", configuration.Proxies[0].Public.Schemes)
	}
}

func TestValidateClientRejectsPublicSchemesForTCP(t *testing.T) {
	configuration := DefaultClient()
	configuration.Authentication.ClientID = "tcp-client"
	configuration.Authentication.Token = "cG9ydHdheS10ZXN0LWNsaWVudC10b2tlbi0wMDAwMDA"
	configuration.Proxies = []ProxyConfig{{
		Name: "ssh", Type: "tcp",
		Local: EndpointConfig{IP: "127.0.0.1", Port: 22},
		Public: ProxyPublicConfig{
			Port: 22022, Schemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTPS},
		},
	}}
	if err := validateClient(configuration); err == nil {
		t.Fatal("TCP proxy with public schemes was accepted")
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
			configuration.Proxies[0].Public.Domain = domain
			if err := validateClient(configuration); err == nil {
				t.Fatalf("invalid HTTP domain %q was accepted", domain)
			}
		})
	}
}

func TestValidateClientUsesOneProxyNameNamespace(t *testing.T) {
	configuration := validHTTPClientConfiguration()
	configuration.Proxies = append(configuration.Proxies, ProxyConfig{
		Name: "web", Type: "tcp",
		Local:  EndpointConfig{IP: "127.0.0.1", Port: 22},
		Public: ProxyPublicConfig{Port: 22022},
	})
	if err := validateClient(configuration); err == nil {
		t.Fatal("duplicate proxy name across HTTP and TCP was accepted")
	}
}

func TestValidateServerAcceptsDefaultHTTPSettings(t *testing.T) {
	configuration := DefaultServer()
	if configuration.Proxies.HTTP.ListenAddress != "" {
		t.Fatalf(
			"default HTTP listener must be disabled, got %q",
			configuration.Proxies.HTTP.ListenAddress,
		)
	}
	if err := validateServer(configuration); err != nil {
		t.Fatalf("default HTTP settings were rejected: %v", err)
	}
	if configuration.Proxies.HTTP.HTTPConfig.ReadHeaderTimeout != 0 ||
		configuration.Proxies.HTTP.HTTPConfig.RequestBodyTimeout != 0 ||
		configuration.Proxies.HTTP.HTTPConfig.PublicIdleTimeout != 0 ||
		configuration.Proxies.HTTP.HTTPConfig.IdleConnectionTimeout != 0 ||
		configuration.Proxies.HTTP.HTTPConfig.ResponseHeaderTimeout != 0 ||
		configuration.Proxies.HTTP.HTTPConfig.UpgradeIdleTimeout != 0 ||
		configuration.Proxies.HTTP.HTTPConfig.MaxRequestBodyBytes != 0 {
		t.Fatalf("HTTP protocol boundaries must default to disabled: %+v", configuration.Proxies.HTTP.HTTPConfig)
	}
}

func TestValidateServerRejectsHTTPHardLimitOverflow(t *testing.T) {
	configuration := DefaultServer()
	configuration.Proxies.HTTP.HTTPConfig.MaxHeaderBytes = httpHardMaxHeaderBytes + 1
	if err := validateServer(configuration); err == nil {
		t.Fatal("HTTP setting above the hard limit was accepted")
	}
	configuration = DefaultServer()
	configuration.Proxies.HTTP.HTTPConfig.UpgradeIdleTimeout = httpHardMaxUpgradeIdleTimeout + time.Second
	if err := validateServer(configuration); err == nil {
		t.Fatal("HTTP Upgrade timeout above the hard limit was accepted")
	}
	configuration = DefaultServer()
	configuration.Proxies.HTTP.HTTPConfig.MaxRequestBodyBytes = httpHardMaxRequestBodyBytes + 1
	if err := validateServer(configuration); err == nil {
		t.Fatal("HTTP request body limit above the hard limit was accepted")
	}
}

func TestValidateServerAllowsDisabledBusinessTimeouts(t *testing.T) {
	configuration := DefaultServer()
	configuration.Proxies.HTTP.HTTPConfig.ReadHeaderTimeout = 0
	configuration.Proxies.HTTP.HTTPConfig.RequestBodyTimeout = 0
	configuration.Proxies.HTTP.HTTPConfig.PublicIdleTimeout = 0
	configuration.Proxies.HTTP.HTTPConfig.IdleConnectionTimeout = 0
	configuration.Proxies.HTTP.HTTPConfig.ResponseHeaderTimeout = 0
	configuration.Proxies.HTTP.HTTPConfig.UpgradeIdleTimeout = 0
	configuration.Proxies.HTTP.HTTPConfig.MaxRequestBodyBytes = 0
	if err := validateServer(configuration); err != nil {
		t.Fatalf("disabled HTTP business timeouts were rejected: %v", err)
	}
}

func TestValidateServerRejectsInvalidSafetyTimeout(t *testing.T) {
	configuration := DefaultServer()
	configuration.Proxies.HTTP.HTTPConfig.GracefulShutdownTimeout = 3 * time.Minute
	if err := validateServer(configuration); err == nil {
		t.Fatal("HTTP safety timeout above the hard limit was accepted")
	}
}

func validHTTPClientConfiguration() ClientConfig {
	configuration := DefaultClient()
	configuration.Authentication.ClientID = "http-client"
	configuration.Authentication.Token = "cG9ydHdheS10ZXN0LWNsaWVudC10b2tlbi0wMDAwMDA"
	configuration.Proxies = []ProxyConfig{{
		Name: "web", Type: "http",
		Local: EndpointConfig{IP: "127.0.0.1", Port: 8080},
		Public: ProxyPublicConfig{
			Domain:  "app.example.com",
			Schemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP},
		},
	}}
	return configuration
}
