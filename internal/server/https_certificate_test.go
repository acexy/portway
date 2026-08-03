package server

import (
	"crypto/tls"
	"os"
	"testing"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
)

func TestHTTPSCertificateManagerSelectsExactAndWildcardSNI(t *testing.T) {
	exactCertificateFile, exactKeyFile := writeServerCertificateForDNSNames(
		t,
		"app.example.com",
	)
	wildcardCertificateFile, wildcardKeyFile := writeServerCertificateForDNSNames(
		t,
		"*.apps.example.com",
	)
	manager, err := newHTTPSCertificateManager(
		logging.New("https-certificate-test"),
		config.HTTPSConfig{Certificates: []config.HTTPSCertificateConfig{
			{
				Domains:  []string{"app.example.com"},
				CertFile: exactCertificateFile,
				KeyFile:  exactKeyFile,
			},
			{
				Domains:  []string{"*.apps.example.com"},
				CertFile: wildcardCertificateFile,
				KeyFile:  wildcardKeyFile,
			},
		}},
	)
	if err != nil {
		t.Fatalf("create HTTPS certificate manager: %v", err)
	}
	exact, err := manager.getCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})
	if err != nil || exact.Leaf.DNSNames[0] != "app.example.com" {
		t.Fatalf("select exact certificate: certificate=%v error=%v", exact, err)
	}
	wildcard, err := manager.getCertificate(
		&tls.ClientHelloInfo{ServerName: "one.apps.example.com"},
	)
	if err != nil || wildcard.Leaf.DNSNames[0] != "*.apps.example.com" {
		t.Fatalf("select wildcard certificate: certificate=%v error=%v", wildcard, err)
	}
	for _, serverName := range []string{"", "unknown.example.com", "deep.one.apps.example.com"} {
		if _, err := manager.getCertificate(&tls.ClientHelloInfo{ServerName: serverName}); err == nil {
			t.Fatalf("SNI %q unexpectedly selected a certificate", serverName)
		}
	}
}

func TestHTTPSCertificateManagerRejectsDomainNotCoveredByCertificate(t *testing.T) {
	certificateFile, keyFile := writeServerCertificateForDNSNames(t, "app.example.com")
	_, err := newHTTPSCertificateManager(
		logging.New("https-certificate-test"),
		config.HTTPSConfig{Certificates: []config.HTTPSCertificateConfig{{
			Domains:  []string{"other.example.com"},
			CertFile: certificateFile,
			KeyFile:  keyFile,
		}}},
	)
	if err == nil {
		t.Fatal("certificate that does not cover its configured domain was accepted")
	}
}

func TestHTTPSCertificateManagerReloadsContentAtomically(t *testing.T) {
	certificateFile, keyFile := writeServerCertificateForDNSNames(t, "app.example.com")
	configuration := config.HTTPSConfig{Certificates: []config.HTTPSCertificateConfig{{
		Domains:  []string{"app.example.com"},
		CertFile: certificateFile,
		KeyFile:  keyFile,
	}}}
	manager, err := newHTTPSCertificateManager(
		logging.New("https-certificate-test"),
		configuration,
	)
	if err != nil {
		t.Fatalf("create HTTPS certificate manager: %v", err)
	}
	initialSnapshot := manager.snapshot.Load()

	replacementCertificateFile, replacementKeyFile := writeServerCertificateForDNSNames(
		t,
		"app.example.com",
	)
	replacementCertificate, err := os.ReadFile(replacementCertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	replacementKey, err := os.ReadFile(replacementKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certificateFile, replacementCertificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, replacementKey, 0o600); err != nil {
		t.Fatal(err)
	}
	manager.reloadCurrent()
	if manager.snapshot.Load() == initialSnapshot {
		t.Fatal("certificate content update was not published")
	}

	activeSnapshot := manager.snapshot.Load()
	if err := os.WriteFile(keyFile, []byte("invalid private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager.reloadCurrent()
	if manager.snapshot.Load() != activeSnapshot {
		t.Fatal("invalid certificate update replaced the active snapshot")
	}
}

func TestHTTPSCertificateManagerReloadsCompleteSet(t *testing.T) {
	certificateFile, keyFile := writeServerCertificateForDNSNames(t, "app.example.com")
	manager, err := newHTTPSCertificateManager(
		logging.New("https-certificate-test"),
		config.HTTPSConfig{Certificates: []config.HTTPSCertificateConfig{{
			Domains:  []string{"app.example.com"},
			CertFile: certificateFile,
			KeyFile:  keyFile,
		}}},
	)
	if err != nil {
		t.Fatalf("create HTTPS certificate manager: %v", err)
	}
	initialSnapshot := manager.snapshot.Load()

	replacementCertificateFile, replacementKeyFile := writeServerCertificateForDNSNames(
		t,
		"service.example.net",
	)
	changed, err := manager.reload(config.HTTPSConfig{
		Certificates: []config.HTTPSCertificateConfig{{
			Domains:  []string{"service.example.net"},
			CertFile: replacementCertificateFile,
			KeyFile:  replacementKeyFile,
		}},
	}, false)
	if err != nil {
		t.Fatalf("reload HTTPS certificate set: %v", err)
	}
	if !changed || manager.snapshot.Load() == initialSnapshot {
		t.Fatal("certificate set update was not published")
	}
	if _, err := manager.getCertificate(
		&tls.ClientHelloInfo{ServerName: "service.example.net"},
	); err != nil {
		t.Fatalf("new SNI mapping is unavailable: %v", err)
	}
}
