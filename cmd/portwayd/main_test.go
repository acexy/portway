package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWithoutArgumentsPrintsServerHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run(nil, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d", exitCode)
	}
	for _, expected := range []string{
		"Portway Server",
		"portwayd <command> [options]",
		"run",
		"cert",
		"version",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), expected)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunVersionPrintsServerVersion(t *testing.T) {
	var stdout bytes.Buffer

	exitCode := run([]string{"version"}, &stdout, &bytes.Buffer{})

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d", exitCode)
	}
	expected := "version: development\ncore-protocol: 1\n"
	if stdout.String() != expected {
		t.Fatalf("stdout = %q, want %q", stdout.String(), expected)
	}
}

func TestRunCertificateGenerateHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run(
		[]string{"cert", "generate", "--help"},
		&stdout,
		&stderr,
	)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d", exitCode)
	}
	if !strings.Contains(
		stdout.String(),
		"portwayd cert generate [options]",
	) {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunCertificateGenerateUsesLocalDefaults(t *testing.T) {
	outputDirectory := filepath.Join(t.TempDir(), "certs")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{
		"cert",
		"generate",
		"--output-dir",
		outputDirectory,
	}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf(
			"run() exit code = %d, stderr = %q",
			exitCode,
			stderr.String(),
		)
	}
	if !strings.Contains(stdout.String(), "Created server certificate:") {
		t.Fatalf("stdout = %q, want generation result", stdout.String())
	}

	serverCertificate := readGeneratedCertificate(
		t,
		filepath.Join(outputDirectory, "server.crt"),
	)
	if err := serverCertificate.VerifyHostname("localhost"); err != nil {
		t.Fatalf("VerifyHostname(localhost) error = %v", err)
	}
	if err := serverCertificate.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("VerifyHostname(127.0.0.1) error = %v", err)
	}
}

func TestRunCertificateGenerateAcceptsRepeatedSANFlags(t *testing.T) {
	outputDirectory := filepath.Join(t.TempDir(), "certs")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{
		"cert",
		"generate",
		"--output-dir",
		outputDirectory,
		"--server-name",
		"gateway.example.com",
		"--server-name",
		"portway.internal",
		"--ip",
		"10.0.0.10",
	}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf(
			"run() exit code = %d, stderr = %q",
			exitCode,
			stderr.String(),
		)
	}

	serverCertificate := readGeneratedCertificate(
		t,
		filepath.Join(outputDirectory, "server.crt"),
	)
	for _, name := range []string{
		"gateway.example.com",
		"portway.internal",
		"10.0.0.10",
	} {
		if err := serverCertificate.VerifyHostname(name); err != nil {
			t.Fatalf("VerifyHostname(%q) error = %v", name, err)
		}
	}
}

func TestRunCertificateRejectsInvalidCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"cert"}, &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "usage: portwayd cert generate") {
		t.Fatalf("stderr = %q, want certificate usage", stderr.String())
	}
}

func readGeneratedCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatalf("Decode(%q) returned no PEM block", path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate(%q) error = %v", path, err)
	}
	return certificate
}
