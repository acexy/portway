package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/acexy/golang-toolkit/util/coll"
)

const (
	defaultOutputDirectory = "certs"
	rootCAValidity         = 10 * 365 * 24 * time.Hour
	serverValidity         = 825 * 24 * time.Hour
	clockSkewAllowance     = 5 * time.Minute
)

// Options controls the internal CA and QUIC server certificate generation.
type Options struct {
	OutputDirectory string
	ServerNames     []string
	IPAddresses     []net.IP
	Now             time.Time
}

// Files contains the paths created by Generate.
type Files struct {
	RootCACertificate string
	RootCAKey         string
	ServerCertificate string
	ServerKey         string
}

type generatedFile struct {
	path       string
	permission os.FileMode
	content    []byte
}

// Generate creates an internal root CA and a server certificate signed by it.
// Existing target files are never overwritten.
func Generate(options Options) (Files, error) {
	if err := applyDefaultsAndValidate(&options); err != nil {
		return Files{}, err
	}

	rootCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Files{}, fmt.Errorf("generate root CA key: %w", err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Files{}, fmt.Errorf("generate server key: %w", err)
	}

	rootCACertificate, err := createRootCACertificate(rootCAKey, options.Now)
	if err != nil {
		return Files{}, err
	}
	serverCertificate, err := createServerCertificate(
		serverKey,
		rootCAKey,
		rootCACertificate,
		options,
	)
	if err != nil {
		return Files{}, err
	}

	rootCAKeyPEM, err := marshalPrivateKey(rootCAKey)
	if err != nil {
		return Files{}, fmt.Errorf("marshal root CA key: %w", err)
	}
	serverKeyPEM, err := marshalPrivateKey(serverKey)
	if err != nil {
		return Files{}, fmt.Errorf("marshal server key: %w", err)
	}

	files := Files{
		RootCACertificate: filepath.Join(options.OutputDirectory, "root-ca.crt"),
		RootCAKey:         filepath.Join(options.OutputDirectory, "root-ca.key"),
		ServerCertificate: filepath.Join(options.OutputDirectory, "server.crt"),
		ServerKey:         filepath.Join(options.OutputDirectory, "server.key"),
	}
	outputs := []generatedFile{
		{
			path:       files.RootCACertificate,
			permission: 0o644,
			content: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: rootCACertificate.Raw,
			}),
		},
		{
			path:       files.RootCAKey,
			permission: 0o600,
			content:    rootCAKeyPEM,
		},
		{
			path:       files.ServerCertificate,
			permission: 0o644,
			content: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: serverCertificate.Raw,
			}),
		},
		{
			path:       files.ServerKey,
			permission: 0o600,
			content:    serverKeyPEM,
		},
	}
	if err := writeGeneratedFiles(options.OutputDirectory, outputs); err != nil {
		return Files{}, err
	}
	return files, nil
}

func applyDefaultsAndValidate(options *Options) error {
	if options.OutputDirectory == "" {
		options.OutputDirectory = defaultOutputDirectory
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	if len(options.ServerNames) == 0 && len(options.IPAddresses) == 0 {
		options.ServerNames = []string{"localhost"}
		options.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}

	seenNames := make(map[string]struct{}, len(options.ServerNames))
	for index, serverName := range options.ServerNames {
		normalized := strings.ToLower(strings.TrimSpace(serverName))
		if !validDNSName(normalized) {
			return fmt.Errorf("invalid server name %q", serverName)
		}
		if _, exists := seenNames[normalized]; exists {
			return fmt.Errorf("duplicate server name %q", serverName)
		}
		seenNames[normalized] = struct{}{}
		options.ServerNames[index] = normalized
	}

	seenAddresses := make(map[string]struct{}, len(options.IPAddresses))
	for _, address := range options.IPAddresses {
		if address == nil {
			return errors.New("invalid IP address")
		}
		normalized := address.String()
		if _, exists := seenAddresses[normalized]; exists {
			return fmt.Errorf("duplicate IP address %q", normalized)
		}
		seenAddresses[normalized] = struct{}{}
	}
	return nil
}

func createRootCACertificate(
	privateKey *ecdsa.PrivateKey,
	now time.Time,
) (*x509.Certificate, error) {
	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate root CA serial number: %w", err)
	}
	subjectKeyID, err := publicKeyID(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("generate root CA subject key ID: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Portway Internal Root CA",
		},
		NotBefore:             now.Add(-clockSkewAllowance),
		NotAfter:              now.Add(rootCAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          subjectKeyID,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("create root CA certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated root CA certificate: %w", err)
	}
	return certificate, nil
}

func createServerCertificate(
	serverKey *ecdsa.PrivateKey,
	rootCAKey *ecdsa.PrivateKey,
	rootCACertificate *x509.Certificate,
	options Options,
) (*x509.Certificate, error) {
	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate server certificate serial number: %w", err)
	}
	subjectKeyID, err := publicKeyID(&serverKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("generate server subject key ID: %w", err)
	}
	commonName := "Portway Server"
	if len(options.ServerNames) > 0 {
		commonName = options.ServerNames[0]
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:    options.Now.Add(-clockSkewAllowance),
		NotAfter:     options.Now.Add(serverValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     append([]string(nil), options.ServerNames...),
		IPAddresses:  cloneIPAddresses(options.IPAddresses),
		SubjectKeyId: subjectKeyID,
		AuthorityKeyId: append(
			[]byte(nil),
			rootCACertificate.SubjectKeyId...,
		),
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		rootCACertificate,
		&serverKey.PublicKey,
		rootCAKey,
	)
	if err != nil {
		return nil, fmt.Errorf("create server certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated server certificate: %w", err)
	}
	return certificate, nil
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if serialNumber.Sign() == 0 {
		return big.NewInt(1), nil
	}
	return serialNumber, nil
}

func publicKeyID(publicKey any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(der)
	return append([]byte(nil), digest[:20]...), nil
}

func marshalPrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

func writeGeneratedFiles(directory string, files []generatedFile) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create certificate directory: %w", err)
	}
	for _, file := range files {
		if _, err := os.Lstat(file.path); err == nil {
			return fmt.Errorf("refusing to overwrite existing file %q", file.path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect certificate output %q: %w", file.path, err)
		}
	}

	created := make([]string, 0, len(files))
	for _, file := range files {
		handle, err := os.OpenFile(
			file.path,
			os.O_WRONLY|os.O_CREATE|os.O_EXCL,
			file.permission,
		)
		if err != nil {
			removeCreatedFiles(created)
			return fmt.Errorf("create certificate output %q: %w", file.path, err)
		}
		created = append(created, file.path)
		if _, err := handle.Write(file.content); err != nil {
			_ = handle.Close()
			removeCreatedFiles(created)
			return fmt.Errorf("write certificate output %q: %w", file.path, err)
		}
		if err := handle.Close(); err != nil {
			removeCreatedFiles(created)
			return fmt.Errorf("close certificate output %q: %w", file.path, err)
		}
	}
	return nil
}

func removeCreatedFiles(paths []string) {
	for _, path := range paths {
		_ = os.Remove(path)
	}
}

func cloneIPAddresses(addresses []net.IP) []net.IP {
	return coll.SliceCollect(addresses, func(address net.IP) net.IP {
		return append(net.IP(nil), address...)
	})
}

func validDNSName(name string) bool {
	if name == "" || len(name) > 253 || strings.HasSuffix(name, ".") {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') ||
				(character >= '0' && character <= '9') ||
				character == '-' {
				continue
			}
			return false
		}
	}
	return true
}
