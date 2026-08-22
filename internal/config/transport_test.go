package config

import (
	"os"
	"path/filepath"
	"strings"
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
  token: cG9ydHdheS10ZXN0LWNsaWVudC10b2tlbi0wMDAwMDA
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
	clientConfiguration.Authentication.Token = "cG9ydHdheS10ZXN0LWNsaWVudC10b2tlbi0wMDAwMDA"
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

func TestAuthenticationTokenRequiresMoreThan32UTF8Characters(t *testing.T) {
	testCases := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:  "generated Base64URL token",
			token: "cG9ydHdheS10ZXN0LWNsaWVudC10b2tlbi0wMDAwMDA",
		},
		{
			name:  "custom ASCII token",
			token: "dsajadf464ga8g13e8gs4gda131ad85ga3a31g4asa1444824",
		},
		{
			name:    "exactly 32 ASCII characters",
			token:   "12345678901234567890123456789012",
			wantErr: true,
		},
		{
			name:  "33 multibyte characters",
			token: strings.Repeat("密", 33),
		},
		{
			name:    "32 multibyte characters",
			token:   strings.Repeat("密", 32),
			wantErr: true,
		},
		{name: "invalid UTF-8", token: string([]byte{0xff, 0xfe}), wantErr: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateToken(testCase.token)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("validateToken() error = %v, wantErr %t", err, testCase.wantErr)
			}
		})
	}
}
