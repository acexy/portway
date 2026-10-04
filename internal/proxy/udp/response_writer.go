package udp

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"time"
)

type responseSocket interface {
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	SetWriteDeadline(time.Time) error
}

// ResponseWriter exclusively owns a shared socket's write deadline. Callers
// retain their buffers until Write returns; association limits bound waiters.
type ResponseWriter struct {
	socket responseSocket
	gate   chan struct{}
}

func NewResponseWriter(socket responseSocket) *ResponseWriter {
	return &ResponseWriter{socket: socket, gate: make(chan struct{}, 1)}
}

// Write bounds admission and I/O together, without closing another association's socket.
func (writer *ResponseWriter) Write(ctx context.Context, payload []byte, address netip.AddrPort, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case writer.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
	defer func() { <-writer.gate }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	if err := writer.socket.SetWriteDeadline(deadline); err != nil {
		return err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = writer.socket.SetWriteDeadline(time.Now())
		close(interrupted)
	})
	written, err := writer.socket.WriteToUDPAddrPort(payload, address)
	// Join the cancellation callback before relinquishing deadline ownership.
	if !stop() {
		<-interrupted
	}
	if err == nil && written != len(payload) {
		err = io.ErrShortWrite
	}
	return errors.Join(err, ctx.Err(), writer.socket.SetWriteDeadline(time.Time{}))
}
