package server

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
)

// httpsCertificateManager owns the immutable certificate used by new TLS handshakes.
type httpsCertificateManager struct {
	logger        *logging.Logger
	certificate   atomic.Pointer[tls.Certificate]
	mutex         sync.Mutex
	configuration config.HTTPSConfig
	digest        string
	lastError     string
}

func newHTTPSCertificateManager(
	logger *logging.Logger,
	configuration config.HTTPSConfig,
) (*httpsCertificateManager, error) {
	manager := &httpsCertificateManager{logger: logger}
	if _, err := manager.reload(configuration, true); err != nil {
		return nil, err
	}
	return manager, nil
}

func (manager *httpsCertificateManager) getCertificate(
	*tls.ClientHelloInfo,
) (*tls.Certificate, error) {
	certificate := manager.certificate.Load()
	if certificate == nil {
		return nil, errors.New("HTTPS certificate is unavailable")
	}
	return certificate, nil
}

// reload validates and atomically publishes one complete certificate pair.
func (manager *httpsCertificateManager) reload(
	configuration config.HTTPSConfig,
	force bool,
) (bool, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	certificate, digest, err := loadHTTPSCertificate(configuration)
	if err != nil {
		return false, err
	}
	if !force && configuration == manager.configuration && digest == manager.digest {
		return false, nil
	}
	manager.publishLocked(configuration, certificate, digest)
	return true, nil
}

func loadHTTPSCertificate(
	configuration config.HTTPSConfig,
) (*tls.Certificate, string, error) {
	certificatePEM, err := os.ReadFile(configuration.CertFile)
	if err != nil {
		return nil, "", fmt.Errorf("read HTTPS certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(configuration.KeyFile)
	if err != nil {
		return nil, "", fmt.Errorf("read HTTPS private key: %w", err)
	}
	certificateDigest := sha256.Sum256(certificatePEM)
	keyDigest := sha256.Sum256(keyPEM)
	digest := hex.EncodeToString(certificateDigest[:]) + ":" +
		hex.EncodeToString(keyDigest[:])

	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, "", fmt.Errorf("load HTTPS certificate pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, "", fmt.Errorf("parse HTTPS leaf certificate: %w", err)
	}
	if len(leaf.ExtKeyUsage) > 0 &&
		!containsExtKeyUsage(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) &&
		!containsExtKeyUsage(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, "", errors.New("HTTPS certificate is not valid for server authentication")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, "", errors.New("HTTPS certificate is outside its validity period")
	}
	certificate.Leaf = leaf
	return &certificate, digest, nil
}

func (manager *httpsCertificateManager) publish(
	configuration config.HTTPSConfig,
	certificate *tls.Certificate,
	digest string,
) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	manager.publishLocked(configuration, certificate, digest)
}

func (manager *httpsCertificateManager) publishLocked(
	configuration config.HTTPSConfig,
	certificate *tls.Certificate,
	digest string,
) {
	manager.certificate.Store(certificate)
	manager.configuration = configuration
	manager.digest = digest
}

func (manager *httpsCertificateManager) reloadCurrent() {
	manager.mutex.Lock()
	configuration := manager.configuration
	certificate, digest, err := loadHTTPSCertificate(configuration)
	if err != nil {
		if err.Error() == manager.lastError {
			manager.mutex.Unlock()
			return
		}
		manager.lastError = err.Error()
		manager.mutex.Unlock()
		manager.logger.WithFields(map[string]any{
			"event":     "https_certificate_reload_failed",
			"cert_file": configuration.CertFile,
			"key_file":  configuration.KeyFile,
		}).Warn("HTTPS certificate reload failed; previous certificate remains active", err)
		return
	}
	changed := digest != manager.digest
	if changed {
		manager.publishLocked(configuration, certificate, digest)
	}
	recovered := manager.lastError != ""
	manager.lastError = ""
	activeCertificate := manager.certificate.Load()
	manager.mutex.Unlock()
	if changed || recovered {
		fields := map[string]any{
			"event":     "https_certificate_reloaded",
			"cert_file": configuration.CertFile,
			"key_file":  configuration.KeyFile,
		}
		if activeCertificate != nil && activeCertificate.Leaf != nil {
			fields["not_after"] = activeCertificate.Leaf.NotAfter
			fields["dns_names"] = activeCertificate.Leaf.DNSNames
		}
		manager.logger.InfoWithFields("HTTPS certificate reloaded", fields)
	}
}

func containsExtKeyUsage(usages []x509.ExtKeyUsage, expected x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == expected {
			return true
		}
	}
	return false
}
