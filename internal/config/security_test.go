package config

import (
	"strings"
	"testing"
)

func TestServerSecurityHTTPClientIPHeaderValidation(t *testing.T) {
	testCases := []struct {
		name         string
		header       string
		httpAddress  string
		httpsAddress string
		denyFile     string
		wantError    string
	}{
		{
			name:        "disabled",
			httpAddress: "",
		},
		{
			name:        "valid",
			header:      "X-Real-IP",
			httpAddress: "127.0.0.1:8080",
			denyFile:    "deny.txt",
		},
		{
			name:         "valid HTTPS only",
			header:       "X-Real-IP",
			httpsAddress: "127.0.0.1:8443",
			denyFile:     "deny.txt",
		},
		{
			name:        "requires deny file",
			header:      "X-Real-IP",
			httpAddress: "127.0.0.1:8080",
			wantError:   "requires security.ip_deny_file",
		},
		{
			name:      "requires HTTP listener",
			header:    "X-Real-IP",
			denyFile:  "deny.txt",
			wantError: "requires an HTTP or HTTPS listener",
		},
		{
			name:        "rejects whitespace",
			header:      " X-Real-IP",
			httpAddress: "127.0.0.1:8080",
			denyFile:    "deny.txt",
			wantError:   "must not contain surrounding whitespace",
		},
		{
			name:        "rejects invalid name",
			header:      "Bad Header",
			httpAddress: "127.0.0.1:8080",
			denyFile:    "deny.txt",
			wantError:   "must be a valid HTTP header name",
		},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			configuration := DefaultServer()
			configuration.Security.HTTPClientIPHeader = testCase.header
			configuration.Security.IPDenyFile = testCase.denyFile
			configuration.Tunnel.HTTPListenAddress = testCase.httpAddress
			configuration.Tunnel.HTTPSListenAddress = testCase.httpsAddress
			if testCase.httpsAddress != "" {
				configuration.HTTPS.Certificates = []HTTPSCertificateConfig{{
					Domains:  []string{"app.example.com"},
					CertFile: "server.crt",
					KeyFile:  "server.key",
				}}
			}
			err := validateServer(configuration)
			if testCase.wantError == "" {
				if err != nil {
					t.Fatalf("validateServer() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf(
					"validateServer() error = %v, want %q",
					err,
					testCase.wantError,
				)
			}
		})
	}
}
