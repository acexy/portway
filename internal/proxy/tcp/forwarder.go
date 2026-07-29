// Package tcp implements TCP proxy stream forwarding.
package tcp

import (
	"context"
	"errors"
	"io"
	"net"
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
	err error
}

// Forward copies a pair of streams in both directions while preserving half-close.
func Forward(ctx context.Context, left Stream, right Stream) error {
	stopContextClose := context.AfterFunc(ctx, func() {
		left.Close()
		right.Close()
	})
	defer stopContextClose()
	defer left.Close()
	defer right.Close()

	results := make(chan copyResult, 2)
	copyDirection := func(destination Stream, source Stream) {
		_, err := io.Copy(destination, source)
		if err == nil {
			if halfCloser, ok := destination.(writeHalfCloser); ok {
				err = halfCloser.CloseWrite()
			} else {
				err = errors.New("stream does not support CloseWrite")
			}
		}
		results <- copyResult{err: err}
	}

	go copyDirection(right, left)
	go copyDirection(left, right)

	firstResult := <-results
	timer := time.NewTimer(streamCloseGracePeriod)
	defer timer.Stop()

	select {
	case secondResult := <-results:
		return errors.Join(firstResult.err, secondResult.err)
	case <-ctx.Done():
		left.Close()
		right.Close()
		secondResult := <-results
		return errors.Join(firstResult.err, secondResult.err)
	case <-timer.C:
		left.Close()
		right.Close()
		secondResult := <-results
		return errors.Join(firstResult.err, secondResult.err)
	}
}
