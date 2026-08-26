package udp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/security/ipfilter"
)

const summaryInterval = time.Minute

// DatagramHandler receives one validated public UDP datagram.
type DatagramHandler func(netip.AddrPort, []byte)

// Endpoint owns one public UDP socket and its read loop.
type Endpoint struct {
	context            context.Context
	logger             *logging.Logger
	connection         *net.UDPConn
	filter             *ipfilter.Filter
	maxSize            int
	mutex              sync.RWMutex
	handler            DatagramHandler
	closeOnce          sync.Once
	startOnce          sync.Once
	waitGroup          sync.WaitGroup
	done               chan struct{}
	receivedDatagrams  atomic.Uint64
	deniedDatagrams    atomic.Uint64
	oversizedDatagrams atomic.Uint64
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
		context:    ctx,
		logger:     logger,
		connection: connection,
		filter:     filter,
		maxSize:    maxSize,
		done:       make(chan struct{}),
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
		endpoint.waitGroup.Go(endpoint.readLoop)
		endpoint.waitGroup.Go(endpoint.summaryLoop)
	})
}

func (endpoint *Endpoint) readLoop() {
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
		endpoint.receivedDatagrams.Add(1)
		if length > endpoint.maxSize {
			endpoint.oversizedDatagrams.Add(1)
			continue
		}
		if endpoint.filter != nil && endpoint.filter.DeniedFor(source.Addr(), "udp_proxy") {
			endpoint.deniedDatagrams.Add(1)
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

func (endpoint *Endpoint) summaryLoop() {
	ticker := time.NewTicker(summaryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-endpoint.context.Done():
			return
		case <-endpoint.done:
			return
		case <-ticker.C:
			received := endpoint.receivedDatagrams.Swap(0)
			denied := endpoint.deniedDatagrams.Swap(0)
			oversized := endpoint.oversizedDatagrams.Swap(0)
			if received == 0 && denied == 0 && oversized == 0 {
				continue
			}
			endpoint.logger.WithComponent("proxy_udp").InfoWithFields(
				"UDP endpoint traffic summary",
				map[string]any{
					"event":               "udp_endpoint_summary",
					"interval_ms":         summaryInterval.Milliseconds(),
					"received_datagrams":  received,
					"denied_datagrams":    denied,
					"oversized_datagrams": oversized,
				},
			)
		}
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
		close(endpoint.done)
		endpoint.connection.Close()
	})
	endpoint.waitGroup.Wait()
}
