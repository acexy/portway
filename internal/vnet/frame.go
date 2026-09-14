package vnet

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	packetFrameVersion    = 1
	packetFrameHeaderSize = 4
)

// WritePacket writes one bounded packet record to a VNet channel.
func WritePacket(writer io.Writer, packet []byte, mtu uint16) error {
	if len(packet) == 0 || len(packet) > int(mtu) {
		return fmt.Errorf("%w: packet length exceeds MTU", ErrInvalidPacket)
	}
	header := [packetFrameHeaderSize]byte{packetFrameVersion}
	binary.BigEndian.PutUint16(header[2:], uint16(len(packet)))
	if err := writeAll(writer, header[:]); err != nil {
		return fmt.Errorf("write VNet packet header: %w", err)
	}
	if err := writeAll(writer, packet); err != nil {
		return fmt.Errorf("write VNet packet payload: %w", err)
	}
	return nil
}

// ReadPacket reads exactly one bounded packet record from a VNet channel.
func ReadPacket(reader io.Reader, mtu uint16) ([]byte, error) {
	header := [packetFrameHeaderSize]byte{}
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	if header[0] != packetFrameVersion || header[1] != 0 {
		return nil, fmt.Errorf("%w: unsupported packet frame", ErrInvalidPacket)
	}
	length := binary.BigEndian.Uint16(header[2:])
	if length == 0 || length > mtu {
		return nil, fmt.Errorf("%w: packet length exceeds MTU", ErrInvalidPacket)
	}
	packet := make([]byte, int(length))
	if _, err := io.ReadFull(reader, packet); err != nil {
		return nil, err
	}
	return packet, nil
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}
