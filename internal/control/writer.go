// Package control contains concurrency-safe control-plane helpers.
package control

import (
	"errors"
	"io"
	"os"
	"time"

	"github.com/acexy/portway/internal/protocol"
)

// Writer serializes control messages written by concurrent owners.
type Writer struct {
	gate   chan struct{}
	writer io.Writer
}

// NewWriter creates a control-plane writer.
func NewWriter(writer io.Writer) *Writer {
	return &Writer{gate: make(chan struct{}, 1), writer: writer}
}

// Write sends one control message.
func (writer *Writer) Write(messageType protocol.MessageType, payload any) error {
	return writer.WriteRequest(messageType, "", payload)
}

// WriteRequest sends one request-correlated control message.
func (writer *Writer) WriteRequest(messageType protocol.MessageType, requestID string, payload any) error {
	writer.gate <- struct{}{}
	defer func() { <-writer.gate }()
	return protocol.WriteControlWithRequestID(writer.writer, messageType, requestID, payload)
}

// WriteUntil bounds both serialization admission and network I/O. A failed
// admitted write closes the stream because its framing may be incomplete.
func (writer *Writer) WriteUntil(deadline time.Time, messageType protocol.MessageType, payload any) error {
	connection, ok := writer.writer.(interface {
		io.Closer
		SetWriteDeadline(time.Time) error
	})
	if !ok {
		return errors.New("control stream does not support bounded writes")
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case writer.gate <- struct{}{}:
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
	defer func() { <-writer.gate }()
	if !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	if err := connection.SetWriteDeadline(deadline); err != nil {
		_ = connection.Close()
		return err
	}
	err := protocol.WriteControl(writer.writer, messageType, payload)
	err = errors.Join(err, connection.SetWriteDeadline(time.Time{}))
	if err != nil {
		_ = connection.Close()
	}
	return err
}

// Close interrupts queued owners by closing their underlying control stream.
func (writer *Writer) Close() error {
	if closer, ok := writer.writer.(io.Closer); ok {
		return closer.Close()
	}
	return errors.New("control stream cannot be closed")
}

// WriteResponse sends one response-correlated control message.
func (writer *Writer) WriteResponse(messageType protocol.MessageType, requestID string, payload any) error {
	return writer.WriteRequest(messageType, requestID, payload)
}
