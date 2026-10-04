package http

import (
	"container/list"
	"context"
	"errors"
	"net"
	stdhttp "net/http"
	"net/http/httptrace"
	"sync"
)

var errConnectionCapacity = errors.New("HTTP backend connection capacity reached")

// ConnectionLimiter bounds pooled backend connections across all domains.
type ConnectionLimiter struct {
	slots chan struct{}
	mutex sync.Mutex
	pools map[*stdhttp.Transport]*list.Element
	idle  list.List
}

// NewConnectionLimiter creates one context-aware global connection limiter.
func NewConnectionLimiter(maximum int) *ConnectionLimiter {
	if maximum < 1 {
		maximum = 1
	}
	return &ConnectionLimiter{
		slots: make(chan struct{}, maximum),
		pools: make(map[*stdhttp.Transport]*list.Element),
	}
}

func (limiter *ConnectionLimiter) acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if release := limiter.tryAcquire(); release != nil {
		return release, nil
	}
	// Transport owns the idle/active transition. Asking it to evict avoids
	// closing a connection that a request has concurrently taken from the pool.
	// Only pools that have reported idle connections become candidates.
	limiter.mutex.Lock()
	budget := limiter.idle.Len()
	limiter.mutex.Unlock()
	for range budget {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		limiter.mutex.Lock()
		candidate := limiter.idle.Front()
		if candidate == nil {
			limiter.mutex.Unlock()
			break
		}
		pool := candidate.Value.(*stdhttp.Transport)
		limiter.idle.Remove(candidate)
		limiter.pools[pool] = nil
		limiter.mutex.Unlock()
		pool.CloseIdleConnections()
		if release := limiter.tryAcquire(); release != nil {
			return release, nil
		}
	}
	if release := limiter.tryAcquire(); release != nil {
		return release, nil
	}
	return nil, errConnectionCapacity
}

func (limiter *ConnectionLimiter) register(pool *stdhttp.Transport) func() {
	limiter.mutex.Lock()
	limiter.pools[pool] = nil
	limiter.mutex.Unlock()
	return func() {
		limiter.mutex.Lock()
		if candidate := limiter.pools[pool]; candidate != nil {
			limiter.idle.Remove(candidate)
		}
		delete(limiter.pools, pool)
		limiter.mutex.Unlock()
	}
}

func (limiter *ConnectionLimiter) track(pool *stdhttp.Transport) stdhttp.RoundTripper {
	return idleTrackingTransport{pool: pool, limiter: limiter}
}

type idleTrackingTransport struct {
	pool    *stdhttp.Transport
	limiter *ConnectionLimiter
}

func (transport idleTrackingTransport) RoundTrip(request *stdhttp.Request) (*stdhttp.Response, error) {
	trace := &httptrace.ClientTrace{PutIdleConn: func(err error) {
		if err != nil {
			return
		}
		limiter := transport.limiter
		limiter.mutex.Lock()
		if candidate, registered := limiter.pools[transport.pool]; registered && candidate == nil {
			limiter.pools[transport.pool] = limiter.idle.PushBack(transport.pool)
		}
		limiter.mutex.Unlock()
	}}
	return transport.pool.RoundTrip(request.WithContext(httptrace.WithClientTrace(request.Context(), trace)))
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
