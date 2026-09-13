package vnet

import (
	"context"
	"errors"
	"net"
	"os"
	"time"
)

// PacketWriter serializes records with a deadline covering both admission and I/O.
type PacketWriter struct {
	context    context.Context
	connection net.Conn
	gate       chan struct{}
	mtu        uint16
	timeout    time.Duration
}

func NewPacketWriter(ctx context.Context, connection net.Conn, mtu uint16, timeout time.Duration) *PacketWriter {
	return &PacketWriter{ctx, connection, make(chan struct{}, 1), mtu, timeout}
}

func (writer *PacketWriter) Send(packet []byte) (result error) {
	deadline := time.Now().Add(writer.timeout)
	defer func() {
		if result != nil {
			// A partial record cannot be retried on this byte stream.
			_ = writer.connection.Close()
		}
	}()
	select {
	case writer.gate <- struct{}{}:
	default:
		// The uncontended packet path does not allocate a timer.
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-writer.context.Done():
			return writer.context.Err()
		case <-timer.C:
			return os.ErrDeadlineExceeded
		case writer.gate <- struct{}{}:
		}
	}
	defer func() { <-writer.gate }()
	if err := writer.context.Err(); err != nil {
		return err
	}
	if !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	if err := writer.connection.SetWriteDeadline(deadline); err != nil {
		return err
	}
	err := WritePacket(writer.connection, packet, writer.mtu)
	return errors.Join(err, writer.connection.SetWriteDeadline(time.Time{}))
}
