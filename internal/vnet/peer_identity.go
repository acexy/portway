package vnet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

func newPeerCertificate(clientID string) (tls.Certificate, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate VNet peer key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate VNet peer serial: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "portway-vnet-peer-" + clientID},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("create VNet peer certificate: %w", err)
	}
	digest := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}, hex.EncodeToString(digest[:]), nil
}

func verifyPeerFingerprint(expected string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCertificates [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCertificates) != 1 {
			return errors.New("invalid VNet peer certificate chain")
		}
		digest := sha256.Sum256(rawCertificates[0])
		if !strings.EqualFold(hex.EncodeToString(digest[:]), expected) {
			return errors.New("VNet peer certificate fingerprint mismatch")
		}
		return nil
	}
}

func peerServerName(generation uint64) string { return fmt.Sprintf("p%x", generation) }

func parsePeerServerName(value string) (uint64, error) {
	if len(value) < 2 || value[0] != 'p' {
		return 0, errors.New("invalid VNet peer server name")
	}
	return strconv.ParseUint(value[1:], 16, 64)
}
