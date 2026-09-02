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
		{name: "empty defaults to HTTP", field: "      schemes: []\n", proxyType: "http", wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
		{name: "explicit HTTPS", field: "      schemes: [https]\n", proxyType: "http", wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTPS}},
		{name: "both schemes", field: "      schemes: [http, https]\n", proxyType: "http", wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP, protocol.HTTPPublicSchemeHTTPS}},
		{name: "duplicate", field: "      schemes: [http, http]\n", proxyType: "http", wantError: "duplicate scheme"},
		{name: "unknown", field: "      schemes: [ftp]\n", proxyType: "http", wantError: "must be http or https"},
		{name: "wrong YAML type", field: "      schemes: https\n", proxyType: "http", wantError: "cannot unmarshal"},
		{name: "forbidden for TCP", field: "      schemes: [http]\n", proxyType: "tcp", wantError: "invalid tcp fields"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "client.yaml")
			remoteField := ""
			domainField := "      domain: app.example.com\n"
			if testCase.proxyType == "tcp" {
				remoteField = "      port: 22022\n"
				domainField = ""
			}
			writeTestConfiguration(t, path, fmt.Sprintf(`
authentication:
  token: cG9ydHdheS10ZXN0LWNsaWVudC10b2tlbi0wMDAwMDA
proxies:
  - name: web
    type: %s
    local:
      ip: 127.0.0.1
      port: 8080
    public:
%s%s%s
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
			if !equalPublicSchemes(configuration.Proxies[0].Public.Schemes, testCase.wantSchemes) {
				t.Fatalf("public schemes = %v, want %v", configuration.Proxies[0].Public.Schemes, testCase.wantSchemes)
			}
		})
	}
}

func TestLoadGovernedStrictHTTPPublicSchemes(t *testing.T) {
	testCases := []struct {
		name        string
		httpFields  string
		enableHTTPS bool
		wantSchemes []protocol.HTTPPublicScheme
		wantError   string
	}{
		{name: "omitted defaults to HTTP", httpFields: "      domains: [app.example.com]\n", wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
		{name: "empty defaults to HTTP", httpFields: "      public_schemes: []\n      domains: [app.example.com]\n", wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
		{name: "explicit HTTPS", httpFields: "      public_schemes: [https]\n      domains: [app.example.com]\n", enableHTTPS: true, wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTPS}},
		{name: "duplicate scheme", httpFields: "      public_schemes: [https, https]\n      domains: [app.example.com]\n", wantError: "duplicate scheme"},
		{name: "unknown scheme", httpFields: "      public_schemes: [ftp]\n      domains: [app.example.com]\n", wantError: "must be http or https"},
		{name: "wrong YAML type", httpFields: "      public_schemes: https\n      domains: [app.example.com]\n", wantError: "cannot unmarshal"},
		{name: "duplicate domain", httpFields: "      domains: [app.example.com, app.example.com]\n", wantError: "duplicate domain"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			directory := t.TempDir()
			governedDirectory := filepath.Join(directory, "governed")
			if err := os.Mkdir(governedDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			writeTestConfiguration(t, filepath.Join(governedDirectory, "client.yaml"), fmt.Sprintf(`
authentication:
  client_id: governed-client
  token: cG9ydHdheS10ZXN0LWdvdmVybmVkLXRva2VuLTAwMDE
permissions:
  proxies:
    http:
%s`, testCase.httpFields))
			serverPath := filepath.Join(directory, "server.yaml")
			serverConfiguration := `
proxies:
  http:
    listen_address: 127.0.0.1:8080
authentication:
  governed_clients_path: governed
`
			if testCase.enableHTTPS {
				certificatePath := filepath.Join(directory, "server.crt")
				keyPath := filepath.Join(directory, "server.key")
				writeTestConfiguration(t, certificatePath, "test certificate")
				writeTestConfiguration(t, keyPath, "test key")
				serverConfiguration = fmt.Sprintf(`
proxies:
  http:
    listen_address: 127.0.0.1:8080
  https:
    listen_address: 127.0.0.1:8443
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
			actual := configuration.GovernedClients["governed-client"].Permissions.Proxies.HTTP.PublicSchemes
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
		{name: "empty defaults to HTTP", field: "        schemes: []\n", wantSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
		{name: "duplicate", field: "        schemes: [http, http]\n", wantError: "duplicate scheme"},
		{name: "unknown", field: "        schemes: [ftp]\n", wantError: "must be http or https"},
		{name: "wrong YAML type", field: "        schemes: http\n", wantError: "cannot unmarshal"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			directory := t.TempDir()
			managedDirectory := filepath.Join(directory, "managed")
			if err := os.Mkdir(managedDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			writeTestConfiguration(t, filepath.Join(managedDirectory, "client.yaml"), fmt.Sprintf(`
authentication:
  client_id: managed-client
  token: cG9ydHdheS10ZXN0LW1hbmFnZWQtdG9rZW4tMDAwMDE
configuration:
  revision: 1
  proxies:
    - name: web
      type: http
      local:
        ip: 127.0.0.1
        port: 8080
      public:
%s        domain: app.example.com
`, testCase.field))
			serverPath := filepath.Join(directory, "server.yaml")
			writeTestConfiguration(t, serverPath, `
proxies:
  http:
    listen_address: 127.0.0.1:8080
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
			actual := configuration.ManagedClients["managed-client"].Configuration.Proxies[0].Public.Schemes
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
				configuration.Proxies.HTTP.ListenAddress = testCase.httpListener
				configuration.Proxies.HTTPS.ListenAddress = testCase.httpsListener
				if mode == "governed" {
					configuration.GovernedClients = map[string]GovernedClientConfig{
						"client": {Permissions: GovernedPermissions{
							Proxies: GovernedProxyPermissions{HTTP: &HTTPPermission{PublicSchemes: testCase.schemes}},
						}},
					}
				} else {
					configuration.ManagedClients = map[string]ManagedClientConfig{
						"client": {Configuration: ManagedConfiguration{Proxies: []ProxyConfig{{
							Name: "web", Type: "http", Public: ProxyPublicConfig{Schemes: testCase.schemes},
						}}}},
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
