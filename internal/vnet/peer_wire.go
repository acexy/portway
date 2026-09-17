package vnet

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
)

const (
	// The first byte deliberately leaves QUIC's fixed bit clear so quic-go
	// delivers the frame through ReadNonQUICPacket.
	peerSignalMagic       = "\x10WVP"
	peerSignalVersion     = 1
	peerSignalHeaderSize  = 8
	peerSignalMACSize     = sha256.Size
	peerSignalMaximumSize = 4096
)

// PeerSignalKind identifies one authenticated non-QUIC UDP message.
type PeerSignalKind uint8

const (
	PeerSignalRegister PeerSignalKind = iota + 1
	PeerSignalProbe
	PeerSignalProbeAck
)

// PeerSignal carries registration and connectivity-check data.
type PeerSignal struct {
	Kind           PeerSignalKind `json:"kind"`
	ClientID       string         `json:"client_id"`
	SessionID      string         `json:"session_id,omitempty"`
	PeerClientID   string         `json:"peer_client_id,omitempty"`
	PeerGeneration uint64         `json:"peer_generation,omitempty"`
	Fingerprint    string         `json:"fingerprint,omitempty"`
	HostCandidates []string       `json:"host_candidates,omitempty"`
}

// EncodePeerSignal authenticates one bounded UDP signal.
func EncodePeerSignal(signal PeerSignal, secret []byte) ([]byte, error) {
	if len(secret) < 16 || signal.ClientID == "" || signal.Kind < PeerSignalRegister || signal.Kind > PeerSignalProbeAck {
		return nil, errors.New("invalid VNet peer signal")
	}
	payload, err := json.Marshal(signal)
	if err != nil || len(payload) == 0 || len(payload) > peerSignalMaximumSize-peerSignalHeaderSize-peerSignalMACSize {
		return nil, errors.New("VNet peer signal payload is too large")
	}
	encoded := make([]byte, peerSignalHeaderSize+len(payload)+peerSignalMACSize)
	copy(encoded[:4], peerSignalMagic)
	encoded[4] = peerSignalVersion
	encoded[5] = byte(signal.Kind)
	binary.BigEndian.PutUint16(encoded[6:8], uint16(len(payload)))
	copy(encoded[peerSignalHeaderSize:], payload)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(encoded[:peerSignalHeaderSize+len(payload)])
	copy(encoded[peerSignalHeaderSize+len(payload):], mac.Sum(nil))
	return encoded, nil
}

// ParsePeerSignal decodes an unauthenticated header so the caller can select a secret.
func ParsePeerSignal(data []byte) (PeerSignal, error) {
	if len(data) < peerSignalHeaderSize+peerSignalMACSize || len(data) > peerSignalMaximumSize ||
		string(data[:4]) != peerSignalMagic || data[4] != peerSignalVersion {
		return PeerSignal{}, errors.New("invalid VNet peer signal frame")
	}
	length := int(binary.BigEndian.Uint16(data[6:8]))
	if length == 0 || peerSignalHeaderSize+length+peerSignalMACSize != len(data) {
		return PeerSignal{}, errors.New("invalid VNet peer signal length")
	}
	var signal PeerSignal
	decoder := json.NewDecoder(bytes.NewReader(data[peerSignalHeaderSize : peerSignalHeaderSize+length]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signal); err != nil || signal.Kind != PeerSignalKind(data[5]) || signal.ClientID == "" {
		return PeerSignal{}, errors.New("invalid VNet peer signal payload")
	}
	return signal, nil
}

// VerifyPeerSignal authenticates a parsed signal frame.
func VerifyPeerSignal(data []byte, secret []byte) error {
	if len(secret) < 16 || len(data) < peerSignalHeaderSize+peerSignalMACSize {
		return errors.New("invalid VNet peer signal secret")
	}
	payloadEnd := len(data) - peerSignalMACSize
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(data[:payloadEnd])
	if !hmac.Equal(data[payloadEnd:], mac.Sum(nil)) {
		return errors.New("invalid VNet peer signal authentication")
	}
	return nil
}
