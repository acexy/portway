package udp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/security/ipfilter"
)

// DatagramHandler receives one validated public UDP datagram.
type DatagramHandler func(netip.AddrPort, []byte)

// Endpoint owns one public UDP socket and its read loop.
type Endpoint struct {
	context   context.Context
	logger    *logging.Logger
	connection *net.UDPConn
	filter    *ipfilter.Filter
	maxSize   int
	mutex     sync.RWMutex
	handler   DatagramHandler
	closeOnce sync.Once
	startOnce sync.Once
	waitGroup sync.WaitGroup
}

// Listen creates a UDP endpoint without starting its read loop.
func Listen(
	ctx context.Context,
	logger *logging.Logger,
	address string,
	filter *ipfilter.Filter,
	maxSize int,
) (*Endpoint, error) {
	listenAddress, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	connection, err := net.ListenUDP("udp", listenAddress)
	if err != nil {
		return nil, err
	}
	return &Endpoint{
		context: ctx,
		logger: logger,
		connection: connection,
		filter: filter,
		maxSize: maxSize,
	}, nil
}

// SetHandler atomically changes the owner of newly received datagrams.
func (endpoint *Endpoint) SetHandler(handler DatagramHandler) {
	endpoint.mutex.Lock()
	endpoint.handler = handler
	endpoint.mutex.Unlock()
}

// Start starts the socket read loop once.
func (endpoint *Endpoint) Start() {
	endpoint.startOnce.Do(func() {
		endpoint.waitGroup.Add(1)
		go endpoint.readLoop()
	})
}

func (endpoint *Endpoint) readLoop() {
	defer endpoint.waitGroup.Done()
	buffer := make([]byte, endpoint.maxSize+1)
	for {
		length, source, err := endpoint.connection.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || endpoint.context.Err() != nil {
				return
			}
			endpoint.logger.Error("UDP proxy socket read failed", err)
			return
		}
		if length > endpoint.maxSize ||
			(endpoint.filter != nil && endpoint.filter.Denied(source.Addr())) {
			continue
		}
		endpoint.mutex.RLock()
		handler := endpoint.handler
		endpoint.mutex.RUnlock()
		if handler == nil {
			continue
		}
		payload := make([]byte, length)
		copy(payload, buffer[:length])
		handler(source, payload)
	}
}

// WriteTo writes one response datagram to its public visitor.
func (endpoint *Endpoint) WriteTo(payload []byte, destination netip.AddrPort) error {
	_, err := endpoint.connection.WriteToUDPAddrPort(payload, destination)
	return err
}

// Close stops the read loop and releases the UDP socket.
func (endpoint *Endpoint) Close() {
	endpoint.closeOnce.Do(func() {
		endpoint.connection.Close()
	})
	endpoint.waitGroup.Wait()
}
