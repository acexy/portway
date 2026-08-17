package compression

import (
	"errors"
	"io"
	"net"
	"sync"

	"github.com/klauspost/compress/zstd"
)

const (
	encoderWindowSize = 1 << 20
	decoderMaxMemory  = 64 << 20
)

// Stream compresses writes and decompresses reads over one bound RoleData stream.
type Stream struct {
	net.Conn
	decoder     *zstd.Decoder
	encoder     *zstd.Encoder
	writeMutex  sync.Mutex
	writeClosed bool
	closeOnce   sync.Once
	closeError  error
}

// NewStream wraps a bound RoleData stream with the requested compression protocol.
func NewStream(connection net.Conn, algorithm Algorithm) (*Stream, error) {
	if algorithm != AlgorithmZstd {
		return nil, errors.New("unsupported compression algorithm")
	}
	decoder, err := zstd.NewReader(
		connection,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(decoderMaxMemory),
	)
	if err != nil {
		return nil, err
	}
	encoder, err := zstd.NewWriter(
		connection,
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderLevel(zstd.SpeedFastest),
		zstd.WithWindowSize(encoderWindowSize),
	)
	if err != nil {
		decoder.Close()
		return nil, err
	}
	return &Stream{Conn: connection, decoder: decoder, encoder: encoder}, nil
}

// Read returns decompressed business data.
func (stream *Stream) Read(destination []byte) (int, error) {
	return stream.decoder.Read(destination)
}

// Write compresses and flushes business data so interactive streams do not stall.
func (stream *Stream) Write(source []byte) (int, error) {
	stream.writeMutex.Lock()
	defer stream.writeMutex.Unlock()
	if stream.writeClosed {
		return 0, io.ErrClosedPipe
	}
	written, err := stream.encoder.Write(source)
	if err != nil {
		return written, err
	}
	if err := stream.encoder.Flush(); err != nil {
		return written, err
	}
	return written, nil
}

// CloseWrite finishes the zstd frame before propagating the transport half-close.
func (stream *Stream) CloseWrite() error {
	stream.writeMutex.Lock()
	defer stream.writeMutex.Unlock()
	if stream.writeClosed {
		return nil
	}
	stream.writeClosed = true
	compressionError := stream.encoder.Close()
	halfCloser, ok := stream.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.Join(compressionError, errors.New("underlying stream does not support CloseWrite"))
	}
	return errors.Join(compressionError, halfCloser.CloseWrite())
}

// Close releases compression state and closes the underlying stream once.
func (stream *Stream) Close() error {
	stream.closeOnce.Do(func() {
		connectionError := stream.Conn.Close()
		stream.decoder.Close()
		stream.writeMutex.Lock()
		stream.writeClosed = true
		compressionError := stream.encoder.Close()
		stream.writeMutex.Unlock()
		stream.closeError = errors.Join(compressionError, connectionError)
	})
	return stream.closeError
}
