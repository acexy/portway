package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
)

func TestLoadServerBuildsMultiModeAuthenticationSnapshot(t *testing.T) {
	configurationDirectory := t.TempDir()
	governedDirectory := filepath.Join(configurationDirectory, "governed")
	managedDirectory := filepath.Join(configurationDirectory, "managed")
	if err := os.Mkdir(governedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(managedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestConfiguration(t, filepath.Join(governedDirectory, "customer-a.yaml"), `
client_id: customer-a
token: cG9ydHdheS10ZXN0LWdvdmVybmVkLXRva2VuLTAwMDE
permissions:
  proxy_types: [tcp, http]
  tcp:
    remote_port_ranges:
      - start: 20000
        end: 20999
  http:
    public_schemes: [http]
    domains:
      - "*.customer-a.example.com"
`)
	writeTestConfiguration(t, filepath.Join(managedDirectory, "internal-a.yaml"), `
client_id: internal-a
token: cG9ydHdheS10ZXN0LW1hbmFnZWQtdG9rZW4tMDAwMDE
configuration:
  revision: 1
  proxies:
    - name: ssh
      type: tcp
      local_ip: 127.0.0.1
      local_port: 22
      remote_port: 22022
`)
	serverPath := filepath.Join(configurationDirectory, "server.yaml")
	writeTestConfiguration(t, serverPath, `
tunnel:
  http_listen_address: 127.0.0.1:8080
authentication:
  shared_token: cG9ydHdheS10ZXN0LXNoYXJlZC10b2tlbi0wMDAwMDE
  governed_clients_path: governed
  managed_clients_path: managed
`)

	configuration, err := LoadServer(serverPath, false)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := BuildAuthenticationSnapshot(configuration)
	if err != nil {
		t.Fatal(err)
	}
	governedSelector := authentication.Selector(
		"cG9ydHdheS10ZXN0LWdvdmVybmVkLXRva2VuLTAwMDE",
	)
	record, exists := snapshot.Resolve(governedSelector[:])
	if !exists {
		t.Fatal("governed authentication record was not indexed")
	}
	if record.Context.Mode != authentication.ModeGoverned ||
		record.Context.ClientID != "customer-a" {
		t.Fatalf("unexpected governed authentication context: %+v", record.Context)
	}
	for _, expected := range []struct {
		token    string
		mode     authentication.Mode
		clientID string
	}{
		{
			token: "cG9ydHdheS10ZXN0LXNoYXJlZC10b2tlbi0wMDAwMDE",
			mode:  authentication.ModeShared,
		},
		{
			token:    "cG9ydHdheS10ZXN0LW1hbmFnZWQtdG9rZW4tMDAwMDE",
			mode:     authentication.ModeManaged,
			clientID: "internal-a",
		},
	} {
		selector := authentication.Selector(expected.token)
		record, exists := snapshot.Resolve(selector[:])
		if !exists {
			t.Fatalf("%s authentication record was not indexed", expected.mode)
		}
		if record.Context.Mode != expected.mode ||
			record.Context.ClientID != expected.clientID {
			t.Fatalf("unexpected %s authentication context: %+v", expected.mode, record.Context)
		}
	}
}

func TestLoadServerRejectsManagedUnavailablePublicScheme(t *testing.T) {
	configurationDirectory := t.TempDir()
	managedDirectory := filepath.Join(configurationDirectory, "managed")
	if err := os.Mkdir(managedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestConfiguration(t, filepath.Join(managedDirectory, "web.yaml"), `
client_id: managed-web
token: cG9ydHdheS10ZXN0LW1hbmFnZWQtdG9rZW4tMDAwMDE
configuration:
  revision: 1
  proxies:
    - name: web
      type: http
      public_schemes: [http]
      domain: app.example.com
      local_ip: 127.0.0.1
      local_port: 8080
`)
	serverPath := filepath.Join(configurationDirectory, "server.yaml")
	writeTestConfiguration(t, serverPath, `
authentication:
  managed_clients_path: managed
`)

	if _, err := LoadServer(serverPath, false); err == nil ||
		!strings.Contains(err.Error(), "requires the public HTTP listener") {
		t.Fatalf("managed unavailable scheme error = %v", err)
	}
}

func TestLoadServerRejectsDuplicateTokensAcrossModes(t *testing.T) {
	configurationDirectory := t.TempDir()
	governedDirectory := filepath.Join(configurationDirectory, "governed")
	managedDirectory := filepath.Join(configurationDirectory, "managed")
	if err := os.Mkdir(governedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(managedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	duplicateToken := "cG9ydHdheS10ZXN0LWR1cGxpY2F0ZS10b2tlbi0wMDA"
	writeTestConfiguration(t, filepath.Join(governedDirectory, "customer-a.yaml"), `
client_id: customer-a
token: `+duplicateToken+`
permissions:
  proxy_types: [tcp]
  tcp:
    remote_port_ranges:
      - start: 20000
        end: 20999
`)
	writeTestConfiguration(t, filepath.Join(managedDirectory, "internal-a.yaml"), `
client_id: internal-a
token: `+duplicateToken+`
configuration:
  revision: 1
  proxies: []
`)
	serverPath := filepath.Join(configurationDirectory, "server.yaml")
	writeTestConfiguration(t, serverPath, `
authentication:
  governed_clients_path: governed
  managed_clients_path: managed
`)

	_, err := LoadServer(serverPath, false)
	if err == nil || !strings.Contains(err.Error(), "globally unique") {
		t.Fatalf("expected duplicate Token rejection, got %v", err)
	}
}

func TestLoadServerRejectsDuplicateClientIDsAcrossManagedModes(t *testing.T) {
	configurationDirectory := t.TempDir()
	governedDirectory := filepath.Join(configurationDirectory, "governed")
	managedDirectory := filepath.Join(configurationDirectory, "managed")
	if err := os.Mkdir(governedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(managedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestConfiguration(t, filepath.Join(governedDirectory, "duplicate.yaml"), `
client_id: duplicate
token: cG9ydHdheS10ZXN0LWdvdmVybmVkLXRva2VuLTAwMDE
permissions:
  proxy_types: []
`)
	writeTestConfiguration(t, filepath.Join(managedDirectory, "duplicate.yaml"), `
client_id: duplicate
token: cG9ydHdheS10ZXN0LW1hbmFnZWQtdG9rZW4tMDAwMDE
configuration:
  revision: 1
  proxies: []
`)
	serverPath := filepath.Join(configurationDirectory, "server.yaml")
	writeTestConfiguration(t, serverPath, `
authentication:
  governed_clients_path: governed
  managed_clients_path: managed
`)

	_, err := LoadServer(serverPath, false)
	if err == nil || !strings.Contains(err.Error(), "both governed and managed") {
		t.Fatalf("expected duplicate ClientID rejection, got %v", err)
	}
}

func TestLoadServerRejectsRemovedTokenField(t *testing.T) {
	serverPath := filepath.Join(t.TempDir(), "server.yaml")
	writeTestConfiguration(t, serverPath, `
authentication:
  token: removed-server-token-field-with-at-least-32-bytes
`)

	if _, err := LoadServer(serverPath, false); err == nil {
		t.Fatal("expected removed authentication.token field to be rejected")
	}
}

func TestValidateManagedProxiesRejectsPublicBindingConflicts(t *testing.T) {
	tests := []struct {
		name    string
		proxies []ProxyConfig
	}{
		{
			name: "duplicate TCP port",
			proxies: []ProxyConfig{
				{Name: "first", Type: "tcp", LocalIP: "127.0.0.1", LocalPort: 1, RemotePort: 20000},
				{Name: "second", Type: "tcp", LocalIP: "127.0.0.1", LocalPort: 2, RemotePort: 20000},
			},
		},
		{
			name: "duplicate UDP port",
			proxies: []ProxyConfig{
				{Name: "first", Type: "udp", LocalIP: "127.0.0.1", LocalPort: 1, RemotePort: 20000},
				{Name: "second", Type: "udp", LocalIP: "127.0.0.1", LocalPort: 2, RemotePort: 20000},
			},
		},
		{
			name: "duplicate HTTP domain",
			proxies: []ProxyConfig{
				{Name: "first", Type: "http", LocalIP: "127.0.0.1", LocalPort: 1, Domain: "app.example.com", PublicSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
				{Name: "second", Type: "http", LocalIP: "127.0.0.1", LocalPort: 2, Domain: "app.example.com", PublicSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateManagedProxies(test.proxies); err == nil {
				t.Fatal("expected managed public binding conflict rejection")
			}
		})
	}
}

func TestProxyLocalIPDefaultsConsistently(t *testing.T) {
	clientConfiguration := DefaultClient()
	clientConfiguration.Authentication.Token = "cG9ydHdheS10ZXN0LWNsaWVudC10b2tlbi0wMDAwMDA"
	clientConfiguration.Proxies = []ProxyConfig{{
		Name: "client-proxy", Type: "tcp", LocalPort: 22, RemotePort: 22022,
	}}
	if err := validateClient(clientConfiguration); err != nil {
		t.Fatalf("validate client proxies: %v", err)
	}
	if clientConfiguration.Proxies[0].LocalIP != "127.0.0.1" {
		t.Fatalf("unexpected client local IP %q", clientConfiguration.Proxies[0].LocalIP)
	}

	managedProxies := []ProxyConfig{{
		Name: "managed-proxy", Type: "tcp", LocalPort: 22, RemotePort: 22023,
	}}
	if err := ValidateManagedProxies(managedProxies); err != nil {
		t.Fatalf("validate managed proxies: %v", err)
	}
	if managedProxies[0].LocalIP != "127.0.0.1" {
		t.Fatalf("unexpected managed local IP %q", managedProxies[0].LocalIP)
	}
}

func TestLoadManagedClientAppliesProxyDefaults(t *testing.T) {
	directory := t.TempDir()
	writeTestConfiguration(t, filepath.Join(directory, "managed-client.yaml"), `
client_id: managed-client
token: cG9ydHdheS10ZXN0LW1hbmFnZWQtdG9rZW4tMDAwMDE
configuration:
  revision: 1
  proxies:
    - name: ssh
      type: tcp
      local_port: 22
      remote_port: 22022
`)

	clients, err := loadManagedClients(directory)
	if err != nil {
		t.Fatal(err)
	}
	proxy := clients["managed-client"].Configuration.Proxies[0]
	if proxy.LocalIP != "127.0.0.1" {
		t.Fatalf("unexpected managed local IP %q", proxy.LocalIP)
	}
}

func TestLoadManagedClientAllowsFileNameIndependentOfClientID(t *testing.T) {
	directory := t.TempDir()
	writeTestConfiguration(t, filepath.Join(directory, "customer-node.yaml"), `
client_id: managed-client
token: cG9ydHdheS10ZXN0LW1hbmFnZWQtdG9rZW4tMDAwMDE
configuration:
  revision: 1
  proxies: []
`)

	clients, err := loadManagedClients(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := clients["managed-client"]; !exists {
		t.Fatal("managed client was not indexed by its configured client ID")
	}
}

func TestValidateManagedClientConflictsRejectsGlobalBindings(t *testing.T) {
	tests := []struct {
		name        string
		firstProxy  ProxyConfig
		secondProxy ProxyConfig
		errorText   string
	}{
		{
			name: "TCP port",
			firstProxy: ProxyConfig{
				Name: "first", Type: "tcp", RemotePort: 20000,
			},
			secondProxy: ProxyConfig{
				Name: "second", Type: "tcp", RemotePort: 20000,
			},
			errorText: "managed TCP remote port",
		},
		{
			name: "UDP port",
			firstProxy: ProxyConfig{
				Name: "first", Type: "udp", RemotePort: 20000,
			},
			secondProxy: ProxyConfig{
				Name: "second", Type: "udp", RemotePort: 20000,
			},
			errorText: "managed UDP remote port",
		},
		{
			name: "HTTP domain",
			firstProxy: ProxyConfig{
				Name: "first", Type: "http", Domain: "app.example.com", PublicSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP},
			},
			secondProxy: ProxyConfig{
				Name: "second", Type: "http", Domain: "app.example.com", PublicSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP},
			},
			errorText: "managed HTTP domain",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clients := map[string]ManagedClientConfig{
				"client-a": {
					ClientID: "client-a",
					Configuration: ManagedConfiguration{
						Revision: 1,
						Proxies:  []ProxyConfig{test.firstProxy},
					},
				},
				"client-b": {
					ClientID: "client-b",
					Configuration: ManagedConfiguration{
						Revision: 1,
						Proxies:  []ProxyConfig{test.secondProxy},
					},
				},
			}
			if err := validateManagedClientConflicts(clients); err == nil ||
				!strings.Contains(err.Error(), test.errorText) {
				t.Fatalf("expected global managed conflict rejection, got %v", err)
			}
		})
	}
}

func TestLoadServerRejectsManagedGlobalBindingConflict(t *testing.T) {
	configurationDirectory := t.TempDir()
	managedDirectory := filepath.Join(configurationDirectory, "managed")
	if err := os.Mkdir(managedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	for index, clientID := range []string{"client-a", "client-b"} {
		writeTestConfiguration(
			t,
			filepath.Join(managedDirectory, fmt.Sprintf("record-%d.yaml", index)),
			fmt.Sprintf(`
client_id: %s
token: %s
configuration:
  revision: 1
  proxies:
    - name: ssh
      type: tcp
      local_ip: 127.0.0.1
      local_port: 22
      remote_port: 22022
`, clientID, []string{
				"cG9ydHdheS10ZXN0LW1hbmFnZWQtdG9rZW4tMDAwMDE",
				"cG9ydHdheS10ZXN0LWdvdmVybmVkLXRva2VuLTAwMDE",
			}[index]),
		)
	}
	serverPath := filepath.Join(configurationDirectory, "server.yaml")
	writeTestConfiguration(t, serverPath, `
authentication:
  managed_clients_path: managed
`)

	if _, err := LoadServer(serverPath, false); err == nil ||
		!strings.Contains(err.Error(), "managed TCP remote port") {
		t.Fatalf("expected startup managed binding conflict rejection, got %v", err)
	}
}

func TestValidateGovernedPermissionsRequiresRulesForAllowedTypes(t *testing.T) {
	tests := []struct {
		name        string
		permissions GovernedPermissions
	}{
		{
			name: "TCP without ranges",
			permissions: GovernedPermissions{
				ProxyTypes: []protocol.ProxyType{protocol.ProxyTypeTCP},
				Limits:     DefaultPermissionLimits(),
			},
		},
		{
			name: "UDP without ranges",
			permissions: GovernedPermissions{
				ProxyTypes: []protocol.ProxyType{protocol.ProxyTypeUDP},
				Limits:     DefaultPermissionLimits(),
			},
		},
		{
			name: "HTTP without domains",
			permissions: GovernedPermissions{
				ProxyTypes: []protocol.ProxyType{protocol.ProxyTypeHTTP},
				Limits:     DefaultPermissionLimits(),
			},
		},
		{
			name: "rules for disabled type",
			permissions: GovernedPermissions{
				Limits: DefaultPermissionLimits(),
				TCP: ProxyPermission{
					RemotePortRanges: []PortRange{{Start: 20000, End: 20999}},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateGovernedPermissions(test.permissions); err == nil {
				t.Fatal("expected governed rule presence rejection")
			}
		})
	}

	valid := GovernedPermissions{
		ProxyTypes: []protocol.ProxyType{
			protocol.ProxyTypeTCP,
			protocol.ProxyTypeUDP,
			protocol.ProxyTypeHTTP,
		},
		Limits: DefaultPermissionLimits(),
		TCP: ProxyPermission{
			RemotePortRanges: []PortRange{{Start: 20000, End: 20999}},
		},
		UDP: ProxyPermission{
			RemotePortRanges: []PortRange{{Start: 30000, End: 30999}},
		},
		HTTP: HTTPPermission{
			PublicSchemes: []protocol.HTTPPublicScheme{
				protocol.HTTPPublicSchemeHTTP,
				protocol.HTTPPublicSchemeHTTPS,
			},
			Domains: []string{"app.example.com"},
		},
	}
	if err := validateGovernedPermissions(valid); err != nil {
		t.Fatalf("valid governed permissions were rejected: %v", err)
	}
}

func TestLoadGovernedClientAppliesDefaultPermissionLimits(t *testing.T) {
	directory := t.TempDir()
	writeTestConfiguration(t, filepath.Join(directory, "customer-a.yaml"), `
client_id: customer-a
token: cG9ydHdheS10ZXN0LWdvdmVybmVkLXRva2VuLTAwMDE
permissions:
  proxy_types: []
`)

	clients, err := loadGovernedClients(directory)
	if err != nil {
		t.Fatal(err)
	}
	if actual := clients["customer-a"].Permissions.Limits; actual != DefaultPermissionLimits() {
		t.Fatalf("unexpected governed permission defaults: %+v", actual)
	}
}

func TestLoadGovernedClientRejectsPermissionLimitOutsideHardBoundary(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value int
	}{
		{name: "zero", field: "max_proxies", value: 0},
		{
			name:  "proxy overflow",
			field: "max_proxies",
			value: hardMaxProxiesPerClient + 1,
		},
		{
			name:  "active link overflow",
			field: "max_active_links",
			value: hardMaxActiveLinksPerClient + 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			writeTestConfiguration(t, filepath.Join(directory, "customer-a.yaml"), fmt.Sprintf(`
client_id: customer-a
token: cG9ydHdheS10ZXN0LWdvdmVybmVkLXRva2VuLTAwMDE
permissions:
  proxy_types: []
  limits:
    %s: %d
`, test.field, test.value))

			if _, err := loadGovernedClients(directory); err == nil ||
				!strings.Contains(err.Error(), test.field) {
				t.Fatalf("expected %s rejection, got %v", test.field, err)
			}
		})
	}
}

func TestValidateManagedProxiesRejectsHardLimitOverflow(t *testing.T) {
	proxies := make([]ProxyConfig, hardMaxProxiesPerClient+1)
	for index := range proxies {
		proxies[index] = ProxyConfig{
			Name:       fmt.Sprintf("tcp-%d", index),
			Type:       "tcp",
			LocalIP:    "127.0.0.1",
			LocalPort:  1,
			RemotePort: uint16(20000 + index),
		}
	}
	if err := ValidateManagedProxies(proxies); err == nil ||
		!strings.Contains(err.Error(), "at most 128") {
		t.Fatalf("expected managed proxy hard limit rejection, got %v", err)
	}
}

func TestLoadServerRejectsManagedProxyHardLimitOverflow(t *testing.T) {
	configurationDirectory := t.TempDir()
	managedDirectory := filepath.Join(configurationDirectory, "managed")
	if err := os.Mkdir(managedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	var managed strings.Builder
	managed.WriteString(`
client_id: managed-client
token: cG9ydHdheS10ZXN0LW1hbmFnZWQtdG9rZW4tMDAwMDE
configuration:
  revision: 1
  proxies:
`)
	for index := range hardMaxProxiesPerClient + 1 {
		fmt.Fprintf(&managed, `
    - name: tcp-%d
      type: tcp
      local_ip: 127.0.0.1
      local_port: 1
      remote_port: %d
`, index, 20000+index)
	}
	writeTestConfiguration(
		t,
		filepath.Join(managedDirectory, "managed-client.yaml"),
		managed.String(),
	)
	serverPath := filepath.Join(configurationDirectory, "server.yaml")
	writeTestConfiguration(t, serverPath, `
authentication:
  managed_clients_path: managed
`)

	if _, err := LoadServer(serverPath, false); err == nil ||
		!strings.Contains(err.Error(), "at most 128") {
		t.Fatalf("expected managed startup hard limit rejection, got %v", err)
	}
}

func TestServerSourceManifestDetectsAuthenticationFileChange(t *testing.T) {
	configurationDirectory := t.TempDir()
	governedDirectory := filepath.Join(configurationDirectory, "governed")
	if err := os.Mkdir(governedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	serverPath := filepath.Join(configurationDirectory, "server.yaml")
	writeTestConfiguration(t, serverPath, `
authentication:
  governed_clients_path: governed
`)
	clientPath := filepath.Join(governedDirectory, "customer-a.yaml")
	writeTestConfiguration(t, clientPath, `
client_id: customer-a
token: cG9ydHdheS10ZXN0LWdvdmVybmVkLXRva2VuLTAwMDE
permissions:
  proxy_types: []
`)
	configuration, err := LoadServer(serverPath, false)
	if err != nil {
		t.Fatal(err)
	}
	before, err := serverSourceManifest(configuration)
	if err != nil {
		t.Fatal(err)
	}
	writeTestConfiguration(t, clientPath, `
client_id: customer-a
token: cG9ydHdheS10ZXN0LWNoYW5nZWQtdG9rZW4tMDAwMDA
permissions:
  proxy_types: []
`)
	after, err := serverSourceManifest(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if before.digest == after.digest {
		t.Fatal("authentication file change did not change the source manifest")
	}
}

func TestAuthenticationFilesRejectsDirectoryTotalSizeLimit(t *testing.T) {
	directory := t.TempDir()
	for index := range 17 {
		path := filepath.Join(directory, fmt.Sprintf("client-%02d.yaml", index))
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(maxAuthenticationFileBytes); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := authenticationFiles(directory); err == nil ||
		!strings.Contains(err.Error(), "total bytes") {
		t.Fatalf("expected authentication directory total size rejection, got %v", err)
	}
}

func TestAuthenticationFilesRejectsDirectorySymlink(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "clients")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticationFiles(link); err == nil ||
		!strings.Contains(err.Error(), "without symbolic links") {
		t.Fatalf("expected authentication directory symlink rejection, got %v", err)
	}
}

func TestReadAuthenticationFileRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.yaml")
	writeTestConfiguration(t, target, "client_id: target")
	link := filepath.Join(directory, "client.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuthenticationFile(link); err == nil ||
		!strings.Contains(err.Error(), "without symbolic links") {
		t.Fatalf("expected authentication file symlink rejection, got %v", err)
	}
}

func TestReadAuthenticationFileEnforcesReadLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxAuthenticationFileBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuthenticationFile(path); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected authentication file size rejection, got %v", err)
	}
}

func writeTestConfiguration(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
