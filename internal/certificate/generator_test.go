package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateCreatesVerifiableCertificateChain(t *testing.T) {
	outputDirectory := filepath.Join(t.TempDir(), "certs")
	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	files, err := Generate(Options{
		OutputDirectory: outputDirectory,
		ServerNames:     []string{"gateway.example.com", "portway.internal"},
		IPAddresses:     []net.IP{net.ParseIP("10.0.0.10")},
		Now:             now,
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	rootCACertificate := readCertificate(t, files.RootCACertificate)
	serverCertificate := readCertificate(t, files.ServerCertificate)
	roots := x509.NewCertPool()
	roots.AddCert(rootCACertificate)
	if _, err := serverCertificate.Verify(x509.VerifyOptions{
		DNSName:     "gateway.example.com",
		Roots:       roots,
		CurrentTime: now,
	}); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if err := serverCertificate.VerifyHostname("portway.internal"); err != nil {
		t.Fatalf("VerifyHostname(portway.internal) error = %v", err)
	}
	if err := serverCertificate.VerifyHostname("10.0.0.10"); err != nil {
		t.Fatalf("VerifyHostname(10.0.0.10) error = %v", err)
	}
	if !rootCACertificate.IsCA {
		t.Fatal("root certificate is not a CA")
	}
	if serverCertificate.IsCA {
		t.Fatal("server certificate must not be a CA")
	}
	if len(serverCertificate.ExtKeyUsage) != 1 ||
		serverCertificate.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf(
			"server ExtKeyUsage = %v, want only ServerAuth",
			serverCertificate.ExtKeyUsage,
		)
	}

	assertPermission(t, files.RootCAKey, 0o600)
	assertPermission(t, files.ServerKey, 0o600)
	assertPermission(t, files.RootCACertificate, 0o644)
	assertPermission(t, files.ServerCertificate, 0o644)
}

func TestGenerateUsesLocalhostDefaults(t *testing.T) {
	files, err := Generate(Options{
		OutputDirectory: filepath.Join(t.TempDir(), "certs"),
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	serverCertificate := readCertificate(t, files.ServerCertificate)
	if err := serverCertificate.VerifyHostname("localhost"); err != nil {
		t.Fatalf("VerifyHostname(localhost) error = %v", err)
	}
	if err := serverCertificate.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("VerifyHostname(127.0.0.1) error = %v", err)
	}
}

func TestGenerateRefusesToOverwriteExistingFile(t *testing.T) {
	outputDirectory := filepath.Join(t.TempDir(), "certs")
	if err := os.MkdirAll(outputDirectory, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	existingPath := filepath.Join(outputDirectory, "server.key")
	existingContent := []byte("existing private key")
	if err := os.WriteFile(existingPath, existingContent, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := Generate(Options{OutputDirectory: outputDirectory}); err == nil {
		t.Fatal("Generate() error = nil, want overwrite refusal")
	}
	content, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(content) != string(existingContent) {
		t.Fatal("existing file content changed")
	}
	if _, err := os.Stat(filepath.Join(outputDirectory, "root-ca.crt")); err == nil {
		t.Fatal("Generate() created files before refusing overwrite")
	}
}

func TestGenerateRejectsInvalidSubjectAlternativeNames(t *testing.T) {
	testCases := []Options{
		{
			OutputDirectory: t.TempDir(),
			ServerNames:     []string{"https://gateway.example.com"},
		},
		{
			OutputDirectory: t.TempDir(),
			IPAddresses:     []net.IP{nil},
		},
		{
			OutputDirectory: t.TempDir(),
			ServerNames:     []string{"gateway.example.com", "gateway.example.com"},
		},
	}
	for _, testCase := range testCases {
		if _, err := Generate(testCase); err == nil {
			t.Fatalf("Generate(%+v) error = nil, want validation error", testCase)
		}
	}
}

func readCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("PEM file %q does not contain a certificate", path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate(%q) error = %v", path, err)
	}
	return certificate
}

func assertPermission(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if actual := info.Mode().Perm(); actual != expected {
		t.Fatalf("%s permission = %o, want %o", path, actual, expected)
	}
}
