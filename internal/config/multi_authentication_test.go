package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acexy/portway/internal/authentication"
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
token: governed-token-with-at-least-32-random-bytes
permissions:
  proxy_types: [tcp, http]
  tcp:
    remote_port_ranges:
      - start: 20000
        end: 20999
  http:
    domains:
      - "*.customer-a.example.com"
`)
	writeTestConfiguration(t, filepath.Join(managedDirectory, "internal-a.yaml"), `
client_id: internal-a
token: managed-token-with-at-least-32-random-bytes
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
authentication:
  shared_token: shared-token-with-at-least-32-random-bytes
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
		"governed-token-with-at-least-32-random-bytes",
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
			token: "shared-token-with-at-least-32-random-bytes",
			mode:  authentication.ModeShared,
		},
		{
			token:    "managed-token-with-at-least-32-random-bytes",
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
	duplicateToken := "duplicate-token-with-at-least-32-random-bytes"
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
token: governed-token-with-at-least-32-random-bytes
permissions:
  proxy_types: []
`)
	writeTestConfiguration(t, filepath.Join(managedDirectory, "duplicate.yaml"), `
client_id: duplicate
token: managed-token-with-at-least-32-random-bytes
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
				{Name: "first", Type: "http", LocalIP: "127.0.0.1", LocalPort: 1, Domain: "app.example.com"},
				{Name: "second", Type: "http", LocalIP: "127.0.0.1", LocalPort: 2, Domain: "app.example.com"},
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
token: governed-token-with-at-least-32-random-bytes
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
token: changed-governed-token-with-at-least-32-random-bytes
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
	for index := 0; index < 17; index++ {
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
