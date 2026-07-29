package token

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"

	"github.com/acexy/portway/internal/transport"
)

const (
	recordHeaderSize   = 12
	maxRecordPlaintext = 64 * 1024
)

var _ transport.Stream = (*secureConnection)(nil)

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
		Conn: rawConnection, readAEAD: readAEAD, writeAEAD: writeAEAD,
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

// CloseWrite propagates a write half-close after all encrypted writes complete.
func (connection *secureConnection) CloseWrite() error {
	connection.writeMutex.Lock()
	defer connection.writeMutex.Unlock()
	halfCloser, ok := connection.Conn.(interface{ CloseWrite() error })
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
	if ciphertextLength < uint32(connection.readAEAD.Overhead()) ||
		ciphertextLength > maxCiphertextLength {
		return fmt.Errorf("%w: invalid record length %d", ErrProtocol, ciphertextLength)
	}
	ciphertext := make([]byte, ciphertextLength)
	if _, err := io.ReadFull(connection.Conn, ciphertext); err != nil {
		return err
	}
	plaintext, err := connection.readAEAD.Open(
		nil, recordNonce(connection.readSequence), ciphertext, header,
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
		nil, recordNonce(connection.writeSequence), plaintext, header,
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
