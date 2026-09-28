package http

import (
	"context"
	"errors"
	"net"
	stdhttp "net/http"
	"sync"
)

var errConnectionCapacity = errors.New("HTTP backend connection capacity reached")

// ConnectionLimiter bounds pooled backend connections across all domains.
type ConnectionLimiter struct {
	slots chan struct{}
	mutex sync.Mutex
	pools map[*stdhttp.Transport]struct{}
}

// NewConnectionLimiter creates one context-aware global connection limiter.
func NewConnectionLimiter(maximum int) *ConnectionLimiter {
	if maximum < 1 {
		maximum = 1
	}
	return &ConnectionLimiter{
		slots: make(chan struct{}, maximum),
		pools: make(map[*stdhttp.Transport]struct{}),
	}
}

func (limiter *ConnectionLimiter) acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if release := limiter.tryAcquire(); release != nil {
		return release, nil
	}
	limiter.mutex.Lock()
	pools := make([]*stdhttp.Transport, 0, len(limiter.pools))
	for pool := range limiter.pools {
		pools = append(pools, pool)
	}
	limiter.mutex.Unlock()
	// Transport owns the idle/active transition. Asking it to evict avoids
	// closing a connection that a request has concurrently taken from the pool.
	for _, pool := range pools {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pool.CloseIdleConnections()
		if release := limiter.tryAcquire(); release != nil {
			return release, nil
		}
	}
	return nil, errConnectionCapacity
}

func (limiter *ConnectionLimiter) register(pool *stdhttp.Transport) func() {
	limiter.mutex.Lock()
	limiter.pools[pool] = struct{}{}
	limiter.mutex.Unlock()
	return func() {
		limiter.mutex.Lock()
		delete(limiter.pools, pool)
		limiter.mutex.Unlock()
	}
}

func (limiter *ConnectionLimiter) tryAcquire() func() {
	select {
	case limiter.slots <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-limiter.slots })
		}
	default:
		return nil
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
