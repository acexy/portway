package server

import (
	"os"
	"testing"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
)

func TestHTTPSCertificateManagerReloadsContentAtomically(t *testing.T) {
	certificateFile, keyFile := writeQUICServerCertificate(t)
	manager, err := newHTTPSCertificateManager(
		logging.New("https-certificate-test"),
		config.HTTPSConfig{CertFile: certificateFile, KeyFile: keyFile},
	)
	if err != nil {
		t.Fatalf("create HTTPS certificate manager: %v", err)
	}
	initialCertificate := manager.certificate.Load()

	replacementCertificateFile, replacementKeyFile := writeQUICServerCertificate(t)
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
	if manager.certificate.Load() == initialCertificate {
		t.Fatal("certificate content update was not published")
	}

	activeCertificate := manager.certificate.Load()
	if err := os.WriteFile(keyFile, []byte("invalid private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager.reloadCurrent()
	if manager.certificate.Load() != activeCertificate {
		t.Fatal("invalid certificate update replaced the active certificate")
	}
}

func TestHTTPSCertificateManagerReloadsPathPair(t *testing.T) {
	certificateFile, keyFile := writeQUICServerCertificate(t)
	manager, err := newHTTPSCertificateManager(
		logging.New("https-certificate-test"),
		config.HTTPSConfig{CertFile: certificateFile, KeyFile: keyFile},
	)
	if err != nil {
		t.Fatalf("create HTTPS certificate manager: %v", err)
	}
	initialCertificate := manager.certificate.Load()

	replacementCertificateFile, replacementKeyFile := writeQUICServerCertificate(t)
	changed, err := manager.reload(config.HTTPSConfig{
		CertFile: replacementCertificateFile,
		KeyFile:  replacementKeyFile,
	}, false)
	if err != nil {
		t.Fatalf("reload HTTPS certificate paths: %v", err)
	}
	if !changed || manager.certificate.Load() == initialCertificate {
		t.Fatal("certificate path update was not published")
	}
}
