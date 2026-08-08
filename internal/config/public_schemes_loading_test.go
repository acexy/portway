package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acexy/portway/internal/protocol"
)

func TestLoadClientStrictHTTPPublicSchemes(t *testing.T) {
	testCases := []struct {
		name        string
		field       string
		proxyType   string
		wantSchemes []protocol.HTTPPublicScheme
		wantError   string
	}{
		{name: "omitted defaults to HTTP", proxyType: "http", wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
		{name: "empty defaults to HTTP", field: "    public_schemes: []\n", proxyType: "http", wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
		{name: "explicit HTTPS", field: "    public_schemes: [https]\n", proxyType: "http", wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTPS}},
		{name: "both schemes", field: "    public_schemes: [http, https]\n", proxyType: "http", wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP, protocol.HTTPPublicSchemeHTTPS}},
		{name: "duplicate", field: "    public_schemes: [http, http]\n", proxyType: "http", wantError: "duplicate scheme"},
		{name: "unknown", field: "    public_schemes: [ftp]\n", proxyType: "http", wantError: "must be http or https"},
		{name: "wrong YAML type", field: "    public_schemes: https\n", proxyType: "http", wantError: "cannot unmarshal"},
		{name: "forbidden for TCP", field: "    public_schemes: [http]\n", proxyType: "tcp", wantError: "invalid tcp fields"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "client.yaml")
			remoteField := ""
			domainField := "    domain: app.example.com\n"
			if testCase.proxyType == "tcp" {
				remoteField = "    remote_port: 22022\n"
				domainField = ""
			}
			writeTestConfiguration(t, path, fmt.Sprintf(`
authentication:
  token: test-token-with-at-least-32-random-bytes
proxies:
  - name: web
    type: %s
%s%s%s    local_ip: 127.0.0.1
    local_port: 8080
`, testCase.proxyType, testCase.field, domainField, remoteField))

			configuration, err := LoadClient(path, false)
			if testCase.wantError != "" {
				if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(testCase.wantError)) {
					t.Fatalf("LoadClient() error = %v, want %q", err, testCase.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !equalPublicSchemes(configuration.Proxies[0].PublicSchemes, testCase.wantSchemes) {
				t.Fatalf("public schemes = %v, want %v", configuration.Proxies[0].PublicSchemes, testCase.wantSchemes)
			}
		})
	}
}

func TestLoadGovernedStrictHTTPPublicSchemes(t *testing.T) {
	testCases := []struct {
		name        string
		proxyTypes  string
		httpFields  string
		enableHTTPS bool
		wantSchemes []protocol.HTTPPublicScheme
		wantError   string
	}{
		{name: "omitted defaults to HTTP", proxyTypes: "[http]", httpFields: "    domains: [app.example.com]\n", wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
		{name: "empty defaults to HTTP", proxyTypes: "[http]", httpFields: "    public_schemes: []\n    domains: [app.example.com]\n", wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
		{name: "explicit HTTPS", proxyTypes: "[http]", httpFields: "    public_schemes: [https]\n    domains: [app.example.com]\n", enableHTTPS: true, wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTPS}},
		{name: "duplicate scheme", proxyTypes: "[http]", httpFields: "    public_schemes: [https, https]\n    domains: [app.example.com]\n", wantError: "duplicate scheme"},
		{name: "unknown scheme", proxyTypes: "[http]", httpFields: "    public_schemes: [ftp]\n    domains: [app.example.com]\n", wantError: "must be http or https"},
		{name: "wrong YAML type", proxyTypes: "[http]", httpFields: "    public_schemes: https\n    domains: [app.example.com]\n", wantError: "cannot unmarshal"},
		{name: "scheme without HTTP type", proxyTypes: "[]", httpFields: "    public_schemes: [https]\n", wantError: "must be empty when http is not allowed"},
		{name: "duplicate domain", proxyTypes: "[http]", httpFields: "    domains: [app.example.com, app.example.com]\n", wantError: "duplicate domain"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			directory := t.TempDir()
			governedDirectory := filepath.Join(directory, "governed")
			if err := os.Mkdir(governedDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			writeTestConfiguration(t, filepath.Join(governedDirectory, "client.yaml"), fmt.Sprintf(`
client_id: governed-client
token: governed-token-with-at-least-32-random-bytes
permissions:
  proxy_types: %s
  http:
%s`, testCase.proxyTypes, testCase.httpFields))
			serverPath := filepath.Join(directory, "server.yaml")
			serverConfiguration := `
tunnel:
  http_listen_address: 127.0.0.1:8080
authentication:
  governed_clients_path: governed
`
			if testCase.enableHTTPS {
				certificatePath := filepath.Join(directory, "server.crt")
				keyPath := filepath.Join(directory, "server.key")
				writeTestConfiguration(t, certificatePath, "test certificate")
				writeTestConfiguration(t, keyPath, "test key")
				serverConfiguration = fmt.Sprintf(`
tunnel:
  http_listen_address: 127.0.0.1:8080
  https_listen_address: 127.0.0.1:8443
https:
  certificates:
    - domains: [app.example.com]
      cert_file: %s
      key_file: %s
authentication:
  governed_clients_path: governed
`, certificatePath, keyPath)
			}
			writeTestConfiguration(t, serverPath, serverConfiguration)

			configuration, err := LoadServer(serverPath, false)
			if testCase.wantError != "" {
				if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(testCase.wantError)) {
					t.Fatalf("LoadServer() error = %v, want %q", err, testCase.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			actual := configuration.GovernedClients["governed-client"].Permissions.HTTP.PublicSchemes
			if !equalPublicSchemes(actual, testCase.wantSchemes) {
				t.Fatalf("public schemes = %v, want %v", actual, testCase.wantSchemes)
			}
		})
	}
}

func TestLoadManagedStrictHTTPPublicSchemes(t *testing.T) {
	testCases := []struct {
		name        string
		field       string
		wantSchemes []protocol.HTTPPublicScheme
		wantError   string
	}{
		{name: "omitted defaults to HTTP", wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
		{name: "empty defaults to HTTP", field: "      public_schemes: []\n", wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
		{name: "duplicate", field: "      public_schemes: [http, http]\n", wantError: "duplicate scheme"},
		{name: "unknown", field: "      public_schemes: [ftp]\n", wantError: "must be http or https"},
		{name: "wrong YAML type", field: "      public_schemes: http\n", wantError: "cannot unmarshal"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			directory := t.TempDir()
			managedDirectory := filepath.Join(directory, "managed")
			if err := os.Mkdir(managedDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			writeTestConfiguration(t, filepath.Join(managedDirectory, "client.yaml"), fmt.Sprintf(`
client_id: managed-client
token: managed-token-with-at-least-32-random-bytes
configuration:
  revision: 1
  proxies:
    - name: web
      type: http
%s      domain: app.example.com
      local_ip: 127.0.0.1
      local_port: 8080
`, testCase.field))
			serverPath := filepath.Join(directory, "server.yaml")
			writeTestConfiguration(t, serverPath, `
tunnel:
  http_listen_address: 127.0.0.1:8080
authentication:
  managed_clients_path: managed
`)

			configuration, err := LoadServer(serverPath, false)
			if testCase.wantError != "" {
				if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(testCase.wantError)) {
					t.Fatalf("LoadServer() error = %v, want %q", err, testCase.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			actual := configuration.ManagedClients["managed-client"].Configuration.Proxies[0].PublicSchemes
			if !equalPublicSchemes(actual, testCase.wantSchemes) {
				t.Fatalf("public schemes = %v, want %v", actual, testCase.wantSchemes)
			}
		})
	}
}

func TestConfiguredPublicSchemesRequireMatchingListeners(t *testing.T) {
	testCases := []struct {
		name          string
		httpListener  string
		httpsListener string
		schemes       []protocol.HTTPPublicScheme
		wantError     string
	}{
		{name: "no listener rejects HTTP", schemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}, wantError: "requires the public HTTP listener"},
		{name: "no listener rejects HTTPS", schemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTPS}, wantError: "requires the public HTTPS listener"},
		{name: "HTTP listener accepts HTTP", httpListener: "127.0.0.1:8080", schemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
		{name: "HTTP listener rejects HTTPS", httpListener: "127.0.0.1:8080", schemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTPS}, wantError: "requires the public HTTPS listener"},
		{name: "HTTPS listener accepts HTTPS", httpsListener: "127.0.0.1:8443", schemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTPS}},
		{name: "HTTPS listener rejects HTTP", httpsListener: "127.0.0.1:8443", schemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}, wantError: "requires the public HTTP listener"},
		{name: "both listeners accept both", httpListener: "127.0.0.1:8080", httpsListener: "127.0.0.1:8443", schemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP, protocol.HTTPPublicSchemeHTTPS}},
	}
	for _, mode := range []string{"governed", "managed"} {
		for _, testCase := range testCases {
			t.Run(mode+"/"+testCase.name, func(t *testing.T) {
				configuration := DefaultServer()
				configuration.Tunnel.HTTPListenAddress = testCase.httpListener
				configuration.Tunnel.HTTPSListenAddress = testCase.httpsListener
				if mode == "governed" {
					configuration.GovernedClients = map[string]GovernedClientConfig{
						"client": {Permissions: GovernedPermissions{HTTP: HTTPPermission{PublicSchemes: testCase.schemes}}},
					}
				} else {
					configuration.ManagedClients = map[string]ManagedClientConfig{
						"client": {Configuration: ManagedConfiguration{Proxies: []ProxyConfig{{Name: "web", Type: "http", PublicSchemes: testCase.schemes}}}},
					}
				}

				err := validateConfiguredPublicSchemeAvailability(configuration)
				if testCase.wantError == "" {
					if err != nil {
						t.Fatal(err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
					t.Fatalf("validation error = %v, want %q", err, testCase.wantError)
				}
			})
		}
	}
}

func equalPublicSchemes(left []protocol.HTTPPublicScheme, right []protocol.HTTPPublicScheme) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
