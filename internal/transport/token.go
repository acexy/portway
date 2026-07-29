// Package transport implements Portway secure transport connections.
package transport

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/acexy/portway/internal/protocol"
)

const (
	handshakeNonceSize  = 32
	handshakeProofSize  = sha256.Size
	handshakeHeaderSize = len(protocol.Magic) + 2 + handshakeNonceSize
	handshakeTimeout    = 5 * time.Second
	recordHeaderSize    = 12
	maxRecordPlaintext  = 64 * 1024
)

var (
	// ErrAuthentication indicates that the peer failed token authentication.
	ErrAuthentication = errors.New("token authentication failed")
	// ErrRecordAuthentication indicates that an encrypted record failed integrity verification.
	ErrRecordAuthentication = errors.New("encrypted record authentication failed")
	// ErrProtocol indicates invalid secure transport data.
	ErrProtocol = errors.New("invalid secure transport protocol")
)

// DialToken establishes a token-authenticated encrypted connection.
func DialToken(ctx context.Context, address string, token string, role protocol.Role) (net.Conn, error) {
	if token == "" {
		return nil, ErrAuthentication
	}

	rawConnection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial %q: %w", address, err)
	}
	stopContextClose := context.AfterFunc(ctx, func() {
		rawConnection.Close()
	})
	defer stopContextClose()

	secureConnection, err := clientTokenHandshake(ctx, rawConnection, token, role)
	if err != nil {
		rawConnection.Close()
		return nil, err
	}
	return secureConnection, nil
}

// AcceptToken authenticates a connection when its declared role is allowed.
func AcceptToken(
	ctx context.Context,
	rawConnection net.Conn,
	token string,
	allowedRoles ...protocol.Role,
) (net.Conn, protocol.Role, error) {
	if token == "" {
		return nil, protocol.RoleUnknown, ErrAuthentication
	}

	secureConnection, role, err := serverTokenHandshake(ctx, rawConnection, token, allowedRoles)
	if err != nil {
		return nil, protocol.RoleUnknown, err
	}
	return secureConnection, role, nil
}

func clientTokenHandshake(
	ctx context.Context,
	rawConnection net.Conn,
	token string,
	role protocol.Role,
) (net.Conn, error) {
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
) (net.Conn, protocol.Role, error) {
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
	if !roleAllowed(role, allowedRoles) {
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

func roleAllowed(role protocol.Role, allowedRoles []protocol.Role) bool {
	if len(allowedRoles) == 0 {
		return true
	}
	for _, allowedRole := range allowedRoles {
		if role == allowedRole {
			return true
		}
	}
	return false
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

func newSecureConnection(
	rawConnection net.Conn,
	readKey []byte,
	writeKey []byte,
) (*secureConnection, error) {
	readAEAD, err := newAEAD(readKey)
	if err != nil {
		return nil, err
	}
	writeAEAD, err := newAEAD(writeKey)
	if err != nil {
		return nil, err
	}
	return &secureConnection{
		Conn:      rawConnection,
		readAEAD:  readAEAD,
		writeAEAD: writeAEAD,
	}, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	authenticatedEncryption, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	return authenticatedEncryption, nil
}

type secureConnection struct {
	net.Conn
	readAEAD      cipher.AEAD
	writeAEAD     cipher.AEAD
	readMutex     sync.Mutex
	writeMutex    sync.Mutex
	readSequence  uint64
	writeSequence uint64
	readBuffer    []byte
}

// CloseWrite propagates a write half-close after all encrypted writes complete.
func (connection *secureConnection) CloseWrite() error {
	connection.writeMutex.Lock()
	defer connection.writeMutex.Unlock()

	halfCloser, ok := connection.Conn.(interface {
		CloseWrite() error
	})
	if !ok {
		return errors.New("underlying transport does not support CloseWrite")
	}
	return halfCloser.CloseWrite()
}

func (connection *secureConnection) Read(destination []byte) (int, error) {
	connection.readMutex.Lock()
	defer connection.readMutex.Unlock()

	if len(destination) == 0 {
		return 0, nil
	}
	if len(connection.readBuffer) == 0 {
		if err := connection.readRecord(); err != nil {
			return 0, err
		}
	}

	copied := copy(destination, connection.readBuffer)
	connection.readBuffer = connection.readBuffer[copied:]
	return copied, nil
}

func (connection *secureConnection) Write(source []byte) (int, error) {
	connection.writeMutex.Lock()
	defer connection.writeMutex.Unlock()

	written := 0
	for len(source) > 0 {
		chunkSize := min(len(source), maxRecordPlaintext)
		if err := connection.writeRecord(source[:chunkSize]); err != nil {
			return written, err
		}
		written += chunkSize
		source = source[chunkSize:]
	}
	return written, nil
}

func (connection *secureConnection) readRecord() error {
	header := make([]byte, recordHeaderSize)
	if _, err := io.ReadFull(connection.Conn, header); err != nil {
		return err
	}

	ciphertextLength := binary.BigEndian.Uint32(header[:4])
	sequence := binary.BigEndian.Uint64(header[4:])
	if sequence != connection.readSequence {
		return fmt.Errorf("%w: expected record sequence %d, got %d", ErrProtocol, connection.readSequence, sequence)
	}
	maxCiphertextLength := uint32(maxRecordPlaintext + connection.readAEAD.Overhead())
	if ciphertextLength < uint32(connection.readAEAD.Overhead()) || ciphertextLength > maxCiphertextLength {
		return fmt.Errorf("%w: invalid record length %d", ErrProtocol, ciphertextLength)
	}

	ciphertext := make([]byte, ciphertextLength)
	if _, err := io.ReadFull(connection.Conn, ciphertext); err != nil {
		return err
	}
	plaintext, err := connection.readAEAD.Open(
		nil,
		recordNonce(connection.readSequence),
		ciphertext,
		header,
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRecordAuthentication, err)
	}
	if connection.readSequence == math.MaxUint64 {
		return fmt.Errorf("%w: read sequence exhausted", ErrProtocol)
	}
	connection.readSequence++
	connection.readBuffer = plaintext
	return nil
}

func (connection *secureConnection) writeRecord(plaintext []byte) error {
	if connection.writeSequence == math.MaxUint64 {
		return fmt.Errorf("%w: write sequence exhausted", ErrProtocol)
	}

	ciphertextLength := len(plaintext) + connection.writeAEAD.Overhead()
	header := make([]byte, recordHeaderSize)
	binary.BigEndian.PutUint32(header[:4], uint32(ciphertextLength))
	binary.BigEndian.PutUint64(header[4:], connection.writeSequence)
	ciphertext := connection.writeAEAD.Seal(
		nil,
		recordNonce(connection.writeSequence),
		plaintext,
		header,
	)
	if err := writeFull(connection.Conn, joinBytes(header, ciphertext)); err != nil {
		return err
	}
	connection.writeSequence++
	return nil
}

func recordNonce(sequence uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], sequence)
	return nonce
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
	totalLength := 0
	for _, part := range parts {
		totalLength += len(part)
	}
	joined := make([]byte, 0, totalLength)
	for _, part := range parts {
		joined = append(joined, part...)
	}
	return joined
}
