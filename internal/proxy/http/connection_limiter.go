package http

import (
	"context"
	"errors"
	"net"
	"sync"
)

// ConnectionLimiter bounds pooled backend connections across all domains.
type ConnectionLimiter struct {
	slots chan struct{}
}

// NewConnectionLimiter creates one context-aware global connection limiter.
func NewConnectionLimiter(maximum int) *ConnectionLimiter {
	if maximum < 1 {
		maximum = 1
	}
	return &ConnectionLimiter{slots: make(chan struct{}, maximum)}
}

func (limiter *ConnectionLimiter) acquire(ctx context.Context) (func(), error) {
	select {
	case limiter.slots <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-limiter.slots })
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type limitedConnection struct {
	net.Conn
	release func()
}

func (connection *limitedConnection) Close() error {
	err := connection.Conn.Close()
	connection.release()
	return err
}

func (connection *limitedConnection) CloseWrite() error {
	closeWriter, ok := connection.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.New("connection does not support half-close")
	}
	return closeWriter.CloseWrite()
}

func (connection *limitedConnection) CloseRead() error {
	closeReader, ok := connection.Conn.(interface{ CloseRead() error })
	if !ok {
		return errors.New("connection does not support read half-close")
	}
	return closeReader.CloseRead()
}
