// Package tcp implements TCP proxy stream forwarding.
package tcp

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"time"
)

// Stream is the reliable byte-stream boundary required by the TCP proxy.
type Stream interface {
	net.Conn
}

type writeHalfCloser interface {
	CloseWrite() error
}

type copyResult struct {
	leftToRight bool
	bytes       int64
	err         error
}

// ForwardResult contains exact byte counts for both copy directions.
type ForwardResult struct {
	LeftToRightBytes int64
	RightToLeftBytes int64
}

// Forward copies a pair of streams in both directions while preserving half-close.
func Forward(ctx context.Context, left Stream, right Stream) (ForwardResult, error) {
	stopContextClose := context.AfterFunc(ctx, func() {
		left.Close()
		right.Close()
	})
	defer stopContextClose()
	defer left.Close()
	defer right.Close()

	results := make(chan copyResult, 2)
	copyDirection := func(destination Stream, source Stream, leftToRight bool) {
		bytesCopied, err := io.Copy(destination, source)
		if err == nil {
			if halfCloser, ok := destination.(writeHalfCloser); ok {
				err = halfCloser.CloseWrite()
			} else {
				err = errors.New("stream does not support CloseWrite")
			}
		}
		results <- copyResult{leftToRight: leftToRight, bytes: bytesCopied, err: err}
	}

	go copyDirection(right, left, true)
	go copyDirection(left, right, false)

	firstResult := <-results
	timer := time.NewTimer(streamCloseGracePeriod)
	defer timer.Stop()

	select {
	case secondResult := <-results:
		return forwardResult(firstResult, secondResult), errors.Join(firstResult.err, secondResult.err)
	case <-ctx.Done():
		left.Close()
		right.Close()
		secondResult := <-results
		return forwardResult(firstResult, secondResult), errors.Join(firstResult.err, secondResult.err)
	case <-timer.C:
		left.Close()
		right.Close()
		secondResult := <-results
		return forwardResult(firstResult, secondResult), errors.Join(firstResult.err, secondResult.err)
	}
}

func forwardResult(leftToRight copyResult, rightToLeft copyResult) ForwardResult {
	if !leftToRight.leftToRight {
		leftToRight, rightToLeft = rightToLeft, leftToRight
	}
	return ForwardResult{
		LeftToRightBytes: leftToRight.bytes,
		RightToLeftBytes: rightToLeft.bytes,
	}
}

// CloseReason classifies a stream error into a stable logging reason.
func CloseReason(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return "link_cancelled"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "connection_reset"
	}
	if errors.Is(err, syscall.EPIPE) {
		return "broken_pipe"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout"
	}
	if errors.Is(err, net.ErrClosed) {
		return "connection_closed"
	}
	return "stream_error"
}
