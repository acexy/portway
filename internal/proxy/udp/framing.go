// Package udp implements UDP datagram proxy runtime behavior.
package udp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const frameHeaderSize = 4

// ErrInvalidFrame indicates malformed UDP data framing.
var ErrInvalidFrame = errors.New("invalid UDP datagram frame")

// ReadDatagram reads one length-prefixed UDP datagram.
func ReadDatagram(reader io.Reader, maxSize int) ([]byte, error) {
	length, err := readDatagramLength(reader, maxSize)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// ReadDatagramInto reads one length-prefixed UDP datagram into caller-owned storage.
func ReadDatagramInto(reader io.Reader, buffer []byte, maxSize int) ([]byte, error) {
	length, err := readDatagramLength(reader, maxSize)
	if err != nil {
		return nil, err
	}
	if length > cap(buffer) {
		return nil, fmt.Errorf(
			"%w: payload length %d exceeds buffer capacity %d",
			ErrInvalidFrame,
			length,
			cap(buffer),
		)
	}
	payload := buffer[:length]
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func readDatagramLength(reader io.Reader, maxSize int) (int, error) {
	var header [frameHeaderSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if uint64(length) > uint64(maxSize) {
		return 0, fmt.Errorf(
			"%w: payload length %d exceeds %d",
			ErrInvalidFrame,
			length,
			maxSize,
		)
	}
	return int(length), nil
}

// WriteDatagram writes one length-prefixed UDP datagram.
func WriteDatagram(writer io.Writer, payload []byte, maxSize int) error {
	if len(payload) > maxSize {
		return fmt.Errorf(
			"%w: payload length %d exceeds %d",
			ErrInvalidFrame,
			len(payload),
			maxSize,
		)
	}
	var header [frameHeaderSize]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
		payload = payload[written:]
	}
	return nil
}
