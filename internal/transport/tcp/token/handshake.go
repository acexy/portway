// Package token implements Portway token-authenticated secure transport over TCP.
package token

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

const (
	handshakeNonceSize  = 32
	handshakeProofSize  = sha256.Size
	handshakeHeaderSize = len(protocol.Magic) + 2 + handshakeNonceSize
	handshakeTimeout    = 5 * time.Second
)

var (
	// ErrAuthentication indicates that the peer failed token authentication.
	ErrAuthentication = transport.ErrAuthentication
	// ErrRecordAuthentication indicates that an encrypted record failed integrity verification.
	ErrRecordAuthentication = errors.New("encrypted record authentication failed")
	// ErrProtocol indicates invalid secure transport data.
	ErrProtocol = transport.ErrProtocol
)

func clientTokenHandshake(
	ctx context.Context,
	rawConnection net.Conn,
	token string,
	role protocol.Role,
) (*secureConnection, error) {
	if !role.Valid() {
		return nil, fmt.Errorf("%w: unsupported connection role %d", ErrProtocol, role)
	}
	if err := setHandshakeDeadline(ctx, rawConnection); err != nil {
		return nil, err
	}
	defer rawConnection.SetDeadline(time.Time{})

	clientHello := makeHandshakeHeader(role)
	if _, err := rand.Read(clientHello[6:]); err != nil {
		return nil, fmt.Errorf("generate client nonce: %w", err)
	}
	if err := writeFull(rawConnection, clientHello); err != nil {
		return nil, fmt.Errorf("write client handshake: %w", err)
	}

	serverMessage := make([]byte, handshakeHeaderSize+handshakeProofSize)
	if _, err := io.ReadFull(rawConnection, serverMessage); err != nil {
		return nil, fmt.Errorf("read server handshake: %w", err)
	}
	serverHello := serverMessage[:handshakeHeaderSize]
	if err := validateHandshakeHeader(serverHello, role); err != nil {
		return nil, err
	}

	transcript := joinBytes(clientHello, serverHello)
	expectedServerProof := handshakeProof(token, "server", transcript)
	if subtle.ConstantTimeCompare(serverMessage[handshakeHeaderSize:], expectedServerProof) != 1 {
		return nil, ErrAuthentication
	}

	clientProof := handshakeProof(token, "client", transcript)
	if err := writeFull(rawConnection, clientProof); err != nil {
		return nil, fmt.Errorf("write client proof: %w", err)
	}

	clientKey, serverKey, err := deriveDirectionalKeys(token, clientHello[6:], serverHello[6:], role)
	if err != nil {
		return nil, err
	}
	return newSecureConnection(rawConnection, serverKey, clientKey)
}

func serverTokenHandshake(
	ctx context.Context,
	rawConnection net.Conn,
	token string,
	allowedRoles []protocol.Role,
) (*secureConnection, protocol.Role, error) {
	if err := setHandshakeDeadline(ctx, rawConnection); err != nil {
		return nil, protocol.RoleUnknown, err
	}
	defer rawConnection.SetDeadline(time.Time{})

	clientHello := make([]byte, handshakeHeaderSize)
	if _, err := io.ReadFull(rawConnection, clientHello); err != nil {
		return nil, protocol.RoleUnknown, fmt.Errorf("read client handshake: %w", err)
	}
	role := protocol.Role(clientHello[5])
	if err := validateHandshakeHeader(clientHello, role); err != nil {
		return nil, protocol.RoleUnknown, err
	}
	if len(allowedRoles) > 0 && !coll.SliceContains(allowedRoles, role) {
		return nil, protocol.RoleUnknown, fmt.Errorf("%w: unsupported connection role %d", ErrProtocol, role)
	}

	serverHello := makeHandshakeHeader(role)
	if _, err := rand.Read(serverHello[6:]); err != nil {
		return nil, protocol.RoleUnknown, fmt.Errorf("generate server nonce: %w", err)
	}
	transcript := joinBytes(clientHello, serverHello)
	serverProof := handshakeProof(token, "server", transcript)
	if err := writeFull(rawConnection, joinBytes(serverHello, serverProof)); err != nil {
		return nil, protocol.RoleUnknown, fmt.Errorf("write server handshake: %w", err)
	}

	clientProof := make([]byte, handshakeProofSize)
	if _, err := io.ReadFull(rawConnection, clientProof); err != nil {
		return nil, protocol.RoleUnknown, fmt.Errorf("read client proof: %w", err)
	}
	expectedClientProof := handshakeProof(token, "client", transcript)
	if subtle.ConstantTimeCompare(clientProof, expectedClientProof) != 1 {
		return nil, protocol.RoleUnknown, ErrAuthentication
	}

	clientKey, serverKey, err := deriveDirectionalKeys(token, clientHello[6:], serverHello[6:], role)
	if err != nil {
		return nil, protocol.RoleUnknown, err
	}
	secureConnection, err := newSecureConnection(rawConnection, clientKey, serverKey)
	if err != nil {
		return nil, protocol.RoleUnknown, err
	}
	return secureConnection, role, nil
}

func makeHandshakeHeader(role protocol.Role) []byte {
	header := make([]byte, handshakeHeaderSize)
	copy(header, protocol.Magic)
	header[4] = protocol.MajorVersion
	header[5] = byte(role)
	return header
}

func validateHandshakeHeader(header []byte, expectedRole protocol.Role) error {
	if len(header) != handshakeHeaderSize {
		return fmt.Errorf("%w: invalid handshake header size", ErrProtocol)
	}
	if string(header[:4]) != protocol.Magic {
		return fmt.Errorf("%w: invalid handshake magic", ErrProtocol)
	}
	if header[4] != protocol.MajorVersion {
		return fmt.Errorf("%w: unsupported protocol version %d", ErrProtocol, header[4])
	}
	role := protocol.Role(header[5])
	if !role.Valid() || role != expectedRole {
		return fmt.Errorf("%w: invalid connection role %d", ErrProtocol, role)
	}
	return nil
}

func handshakeProof(token string, peer string, transcript []byte) []byte {
	messageAuthenticationCode := hmac.New(sha256.New, []byte(token))
	messageAuthenticationCode.Write([]byte("portway-token-v1/" + peer))
	messageAuthenticationCode.Write(transcript)
	return messageAuthenticationCode.Sum(nil)
}

func deriveDirectionalKeys(
	token string,
	clientNonce []byte,
	serverNonce []byte,
	role protocol.Role,
) ([]byte, []byte, error) {
	salt := joinBytes(clientNonce, serverNonce)
	contextLabel := fmt.Sprintf("portway-token-v1/role/%d/", role)
	clientKey, err := hkdf.Key(sha256.New, []byte(token), salt, contextLabel+"client-to-server", 32)
	if err != nil {
		return nil, nil, fmt.Errorf("derive client transport key: %w", err)
	}
	serverKey, err := hkdf.Key(sha256.New, []byte(token), salt, contextLabel+"server-to-client", 32)
	if err != nil {
		return nil, nil, fmt.Errorf("derive server transport key: %w", err)
	}
	return clientKey, serverKey, nil
}

func setHandshakeDeadline(ctx context.Context, connection net.Conn) error {
	deadline := time.Now().Add(handshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set handshake deadline: %w", err)
	}
	return nil
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func joinBytes(parts ...[]byte) []byte {
	return coll.SliceFlat(parts)
}
