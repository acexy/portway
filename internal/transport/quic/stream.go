package quic

import (
	"net"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"

	"github.com/acexy/portway/internal/transport"
)

var _ transport.Stream = (*stream)(nil)

type stream struct {
	stream          *quicgo.Stream
	connection      *quicgo.Conn
	closeConnection bool
	mutex           sync.Mutex
	closed          bool
	writeClosed     bool
	closeOnce       sync.Once
	closeError      error
}

func newStream(
	quicStream *quicgo.Stream,
	connection *quicgo.Conn,
	closeConnection bool,
) *stream {
	return &stream{
		stream:          quicStream,
		connection:      connection,
		closeConnection: closeConnection,
	}
}

func (stream *stream) Read(destination []byte) (int, error) {
	return stream.stream.Read(destination)
}

func (stream *stream) Write(source []byte) (int, error) {
	return stream.stream.Write(source)
}

// CloseWrite sends a QUIC FIN while preserving the receive direction.
func (stream *stream) CloseWrite() error {
	stream.mutex.Lock()
	defer stream.mutex.Unlock()
	if stream.closed {
		return net.ErrClosed
	}
	if stream.writeClosed {
		return nil
	}
	err := stream.stream.Close()
	if err == nil {
		stream.writeClosed = true
	}
	return err
}

// Close terminates this logical stream. Closing a control stream also owns and
// closes its complete QUIC connection.
func (stream *stream) Close() error {
	stream.closeOnce.Do(func() {
		stream.mutex.Lock()
		defer stream.mutex.Unlock()
		stream.closed = true
		if stream.closeConnection {
			stream.closeError = stream.connection.CloseWithError(
				applicationErrorShutdown,
				"control stream closed",
			)
			return
		}
		stream.stream.CancelRead(streamErrorClosed)
		// Preserve an explicit FIN, but abort writes when closing an active stream.
		if !stream.writeClosed {
			stream.stream.CancelWrite(streamErrorClosed)
		}
	})
	return stream.closeError
}

func (stream *stream) LocalAddr() net.Addr {
	return stream.connection.LocalAddr()
}

func (stream *stream) RemoteAddr() net.Addr {
	return stream.connection.RemoteAddr()
}

func (stream *stream) SetDeadline(deadline time.Time) error {
	return stream.stream.SetDeadline(deadline)
}

func (stream *stream) SetReadDeadline(deadline time.Time) error {
	return stream.stream.SetReadDeadline(deadline)
}

func (stream *stream) SetWriteDeadline(deadline time.Time) error {
	return stream.stream.SetWriteDeadline(deadline)
}
