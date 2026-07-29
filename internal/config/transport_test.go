package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/acexy/portway/internal/transport"
)

func TestDefaultTransportUsesTCP(t *testing.T) {
	clientConfiguration := DefaultClient()
	if clientConfiguration.Transport.Type != transport.TypeTCP {
		t.Fatalf("unexpected client transport type %q", clientConfiguration.Transport.Type)
	}
	if clientConfiguration.Transport.ServerAddress == "" {
		t.Fatal("default client TCP server address is empty")
	}

	serverConfiguration := DefaultServer()
	if serverConfiguration.Transport.Type != transport.TypeTCP {
		t.Fatalf("unexpected server transport type %q", serverConfiguration.Transport.Type)
	}
	if serverConfiguration.Transport.ListenAddress == "" {
		t.Fatal("default server TCP listen address is empty")
	}
}

func TestTransportTypeDefaultsToTCPWhenOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	content := []byte(`
transport:
  server_address: gateway.example.com:7000
authentication:
  token: test-token-with-at-least-32-random-bytes
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	configuration, err := LoadClient(path, false)
	if err != nil {
		t.Fatalf("load client configuration: %v", err)
	}
	if configuration.Transport.Type != transport.TypeTCP {
		t.Fatalf("unexpected default transport type %q", configuration.Transport.Type)
	}
}

func TestQUICTransportConfigurationIsAccepted(t *testing.T) {
	clientConfiguration := DefaultClient()
	clientConfiguration.Authentication.Token = "test-token-with-at-least-32-random-bytes"
	clientConfiguration.Transport.Type = transport.TypeQUIC
	clientConfiguration.Transport.QUIC = QUICClientTransportConfig{
		ServerName: "gateway.example.com",
	}
	if err := validateClient(clientConfiguration); err != nil {
		t.Fatalf("valid client QUIC configuration was rejected: %v", err)
	}

	serverConfiguration := DefaultServer()
	serverConfiguration.Transport.Type = transport.TypeQUIC
	serverConfiguration.Transport.QUIC = QUICServerTransportConfig{
		CertFile: "server.crt",
		KeyFile:  "server.key",
	}
	if err := validateServer(serverConfiguration); err != nil {
		t.Fatalf("valid server QUIC configuration was rejected: %v", err)
	}
}
