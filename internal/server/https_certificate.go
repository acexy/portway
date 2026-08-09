package server

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
)

const maxHTTPSCertificateFileBytes = 4 * 1024 * 1024

// httpsCertificateSnapshot is an immutable SNI certificate selection index.
type httpsCertificateSnapshot struct {
	exact     map[string]*tls.Certificate
	wildcards map[string]*tls.Certificate
	count     int
	domains   int
}

// httpsCertificateManager owns the immutable certificate set used by new TLS handshakes.
type httpsCertificateManager struct {
	logger        *logging.Logger
	snapshot      atomic.Pointer[httpsCertificateSnapshot]
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
	hello *tls.ClientHelloInfo,
) (*tls.Certificate, error) {
	if hello == nil || hello.ServerName == "" {
		return nil, errors.New("HTTPS client did not provide SNI")
	}
	serverName := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	snapshot := manager.snapshot.Load()
	if snapshot == nil {
		return nil, errors.New("HTTPS certificates are unavailable")
	}
	if certificate := snapshot.exact[serverName]; certificate != nil {
		return certificate, nil
	}
	if separator := strings.IndexByte(serverName, '.'); separator > 0 {
		if certificate := snapshot.wildcards[serverName[separator+1:]]; certificate != nil {
			return certificate, nil
		}
	}
	return nil, fmt.Errorf("no HTTPS certificate configured for SNI %q", serverName)
}

// reload validates and atomically publishes one complete certificate set.
func (manager *httpsCertificateManager) reload(
	configuration config.HTTPSConfig,
	force bool,
) (bool, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	snapshot, digest, err := loadHTTPSCertificates(configuration)
	if err != nil {
		return false, err
	}
	if !force && reflect.DeepEqual(configuration, manager.configuration) &&
		digest == manager.digest {
		return false, nil
	}
	manager.publishLocked(configuration, snapshot, digest)
	return true, nil
}

func loadHTTPSCertificates(
	configuration config.HTTPSConfig,
) (*httpsCertificateSnapshot, string, error) {
	if err := config.ValidateHTTPSConfig(configuration); err != nil {
		return nil, "", err
	}
	snapshot := &httpsCertificateSnapshot{
		exact:     make(map[string]*tls.Certificate),
		wildcards: make(map[string]*tls.Certificate),
		count:     len(configuration.Certificates),
	}
	hasher := sha256.New()
	for index, configuredCertificate := range configuration.Certificates {
		certificate, certificateDigest, err := loadHTTPSCertificatePair(configuredCertificate)
		if err != nil {
			return nil, "", fmt.Errorf("https.certificates[%d]: %w", index, err)
		}
		hasher.Write([]byte(certificateDigest))
		for _, domain := range configuredCertificate.Domains {
			if err := verifyHTTPSCertificateDomain(certificate.Leaf, domain); err != nil {
				return nil, "", fmt.Errorf(
					"https.certificates[%d] does not cover domain %q: %w",
					index,
					domain,
					err,
				)
			}
			hasher.Write([]byte{0})
			hasher.Write([]byte(domain))
			if strings.HasPrefix(domain, "*.") {
				snapshot.wildcards[strings.TrimPrefix(domain, "*.")] = certificate
			} else {
				snapshot.exact[domain] = certificate
			}
			snapshot.domains++
		}
	}
	return snapshot, hex.EncodeToString(hasher.Sum(nil)), nil
}

func loadHTTPSCertificatePair(
	configuration config.HTTPSCertificateConfig,
) (*tls.Certificate, string, error) {
	certificatePEM, err := readHTTPSCertificateFile(configuration.CertFile)
	if err != nil {
		return nil, "", fmt.Errorf("read HTTPS certificate: %w", err)
	}
	keyPEM, err := readHTTPSCertificateFile(configuration.KeyFile)
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

func readHTTPSCertificateFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("certificate source is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxHTTPSCertificateFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxHTTPSCertificateFileBytes {
		return nil, fmt.Errorf("certificate source exceeds %d bytes", maxHTTPSCertificateFileBytes)
	}
	return data, nil
}

func verifyHTTPSCertificateDomain(certificate *x509.Certificate, domain string) error {
	if strings.HasPrefix(domain, "*.") {
		domain = "portway-validation." + strings.TrimPrefix(domain, "*.")
	}
	return certificate.VerifyHostname(domain)
}

func (manager *httpsCertificateManager) publish(
	configuration config.HTTPSConfig,
	snapshot *httpsCertificateSnapshot,
	digest string,
) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	manager.publishLocked(configuration, snapshot, digest)
}

func (manager *httpsCertificateManager) publishLocked(
	configuration config.HTTPSConfig,
	snapshot *httpsCertificateSnapshot,
	digest string,
) {
	manager.snapshot.Store(snapshot)
	manager.configuration = configuration
	manager.digest = digest
}

func (manager *httpsCertificateManager) reloadCurrent() {
	manager.mutex.Lock()
	configuration := manager.configuration
	snapshot, digest, err := loadHTTPSCertificates(configuration)
	if err != nil {
		if err.Error() == manager.lastError {
			manager.mutex.Unlock()
			return
		}
		manager.lastError = err.Error()
		manager.mutex.Unlock()
		manager.logger.Warn(
			"HTTPS certificate reload failed; previous certificate set remains active",
			err,
		)
		return
	}
	changed := digest != manager.digest
	if changed {
		manager.publishLocked(configuration, snapshot, digest)
	}
	recovered := manager.lastError != ""
	manager.lastError = ""
	activeSnapshot := manager.snapshot.Load()
	manager.mutex.Unlock()
	if changed || recovered {
		manager.logger.InfoWithFields("HTTPS certificate set reloaded", map[string]any{
			"event":             "https_certificate_reloaded",
			"certificate_count": activeSnapshot.count,
			"domain_count":      activeSnapshot.domains,
		})
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
