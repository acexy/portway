// Package control contains concurrency-safe control-plane helpers.
package control

import (
	"io"
	"sync"

	"github.com/acexy/portway/internal/protocol"
)

// Writer serializes control messages written by concurrent owners.
type Writer struct {
	mutex  sync.Mutex
	writer io.Writer
}

// NewWriter creates a control-plane writer.
func NewWriter(writer io.Writer) *Writer {
	return &Writer{writer: writer}
}

// Write sends one control message.
func (writer *Writer) Write(messageType protocol.MessageType, payload any) error {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	return protocol.WriteControl(writer.writer, messageType, payload)
}

// WriteRequest sends one request-correlated control message.
func (writer *Writer) WriteRequest(
	messageType protocol.MessageType,
	requestID string,
	payload any,
) error {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	return protocol.WriteControlWithRequestID(writer.writer, messageType, requestID, payload)
}

// WriteResponse sends one response-correlated control message.
func (writer *Writer) WriteResponse(
	messageType protocol.MessageType,
	requestID string,
	payload any,
) error {
	return writer.WriteRequest(messageType, requestID, payload)
}
