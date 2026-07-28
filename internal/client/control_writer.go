package client

import (
	"io"
	"sync"

	"github.com/acexy/portway/internal/protocol"
)

type controlWriter struct {
	mutex  sync.Mutex
	writer io.Writer
}

func newControlWriter(writer io.Writer) *controlWriter {
	return &controlWriter{writer: writer}
}

func (writer *controlWriter) write(messageType protocol.MessageType, payload any) error {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	return protocol.WriteControl(writer.writer, messageType, payload)
}

func (writer *controlWriter) writeRequest(
	messageType protocol.MessageType,
	requestID string,
	payload any,
) error {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	return protocol.WriteControlWithRequestID(writer.writer, messageType, requestID, payload)
}
