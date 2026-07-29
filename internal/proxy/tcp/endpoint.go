package tcp

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/security/ipfilter"
)

// Endpoint owns one public TCP listener and its visitor accept loop.
type Endpoint struct {
	context   context.Context
	logger    *logging.Logger
	listener  net.Listener
	mutex     sync.RWMutex
	handler   func(net.Conn)
	closeOnce sync.Once
	startOnce sync.Once
	waitGroup sync.WaitGroup
}

// Listen creates a TCP endpoint without starting its accept loop.
func Listen(
	ctx context.Context,
	logger *logging.Logger,
	address string,
	sourceFilter *ipfilter.Filter,
) (*Endpoint, error) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	listener = ipfilter.WrapListener(listener, sourceFilter)
	return &Endpoint{context: ctx, logger: logger, listener: listener}, nil
}

// SetHandler atomically changes the owner of newly accepted visitors.
func (endpoint *Endpoint) SetHandler(handler func(net.Conn)) {
	endpoint.mutex.Lock()
	endpoint.handler = handler
	endpoint.mutex.Unlock()
}

// Start starts the accept loop once.
func (endpoint *Endpoint) Start() {
	endpoint.startOnce.Do(func() {
		endpoint.waitGroup.Add(1)
		go func() {
			defer endpoint.waitGroup.Done()
			for {
				connection, err := endpoint.listener.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) || endpoint.context.Err() != nil {
						return
					}
					endpoint.logger.Error("TCP proxy listener failed", err)
					return
				}
				endpoint.mutex.RLock()
				handler := endpoint.handler
				endpoint.mutex.RUnlock()
				if handler == nil {
					connection.Close()
					continue
				}
				handler(connection)
			}
		}()
	})
}

// Close stops accepting visitors and waits for the accept loop.
func (endpoint *Endpoint) Close() {
	endpoint.closeOnce.Do(func() {
		endpoint.listener.Close()
	})
	endpoint.waitGroup.Wait()
}
