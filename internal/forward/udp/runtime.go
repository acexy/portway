// Package udp implements UDP Forward endpoints, associations, and target runtime behavior.
package udp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/link"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
)

// Association owns queued datagrams for one local visitor address.
type Association struct {
	Context  context.Context
	Packets  <-chan []byte
	write    func([]byte) error
	release  func(int)
	touch    func()
	activate func()
}

// Write sends one response datagram to the association visitor.
func (association *Association) Write(payload []byte) error {
	err := association.write(payload)
	if err == nil {
		association.touch()
	}
	return err
}

// ReleaseQueue releases accounting for one dequeued visitor datagram.
func (association *Association) ReleaseQueue(size int) {
	association.release(size)
}

// Activate transitions the Association from pending to active accounting.
func (association *Association) Activate() {
	association.activate()
}

type associationRuntime struct {
	association  Association
	cancel       context.CancelFunc
	queue        chan []byte
	lease        *proxyudp.AssociationLease
	lastActivity atomic.Int64
}

// Endpoint owns one client-side UDP socket and its visitor associations.
type Endpoint struct {
	context       context.Context
	cancel        context.CancelFunc
	packet        *net.UDPConn
	maxDatagram   int
	queueSize     int
	configuration config.UDPConfig
	clientID      string
	forwardName   string
	limiter       *proxyudp.Limiter
	mutex         sync.Mutex
	associations  map[netip.AddrPort]*associationRuntime
	waitGroup     sync.WaitGroup
	closed        bool
}

// Listen prepares one UDP Forward endpoint.
func Listen(
	ctx context.Context,
	address string,
	clientID string,
	forwardName string,
	configuration config.UDPConfig,
	limiter *proxyudp.Limiter,
) (*Endpoint, error) {
	endpointContext, cancel := context.WithCancel(ctx)
	packet, err := (&net.ListenConfig{}).ListenPacket(endpointContext, "udp", address)
	if err != nil {
		cancel()
		return nil, err
	}
	endpoint := &Endpoint{
		context: endpointContext, cancel: cancel, packet: packet.(*net.UDPConn), maxDatagram: configuration.MaxDatagramSize,
		queueSize:     configuration.MaxQueuedDatagramsPerAssociation,
		configuration: configuration, clientID: clientID, forwardName: forwardName,
		limiter:      limiter,
		associations: make(map[netip.AddrPort]*associationRuntime),
	}
	endpoint.waitGroup.Go(endpoint.sweep)
	return endpoint, nil
}

// Serve routes local datagrams into source-address associations.
func (endpoint *Endpoint) Serve(handler func(*Association)) error {
	buffer := make([]byte, endpoint.maxDatagram+1)
	for {
		length, address, err := endpoint.packet.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return err
		}
		if length > endpoint.maxDatagram {
			continue
		}
		association, ok := endpoint.association(address, handler)
		if !ok {
			return net.ErrClosed
		}
		if association == nil {
			continue
		}
		// The endpoint is the only queue producer; consumers can only free slots.
		if len(association.queue) == cap(association.queue) || !association.lease.ReserveQueue(length) {
			continue
		}
		payload := append([]byte(nil), buffer[:length]...)
		select {
		case association.queue <- payload:
			association.lastActivity.Store(time.Now().UnixNano())
		default:
			association.lease.ReleaseQueue(len(payload))
		}
	}
}

func (endpoint *Endpoint) association(
	address netip.AddrPort,
	handler func(*Association),
) (*associationRuntime, bool) {
	key := address
	endpoint.mutex.Lock()
	defer endpoint.mutex.Unlock()
	if endpoint.closed {
		return nil, false
	}
	if current := endpoint.associations[key]; current != nil {
		return current, true
	}
	lease, allowed := endpoint.limiter.Acquire(
		endpoint.clientID, endpoint.forwardName, address.Addr(), time.Now(),
	)
	if !allowed {
		return nil, true
	}
	ctx, cancel := context.WithCancel(endpoint.context)
	queue := make(chan []byte, endpoint.queueSize)
	current := &associationRuntime{cancel: cancel, queue: queue, lease: lease}
	current.lastActivity.Store(time.Now().UnixNano())
	current.association = Association{
		Context: ctx,
		Packets: queue,
		write: func(payload []byte) error {
			written, err := endpoint.packet.WriteToUDPAddrPort(payload, address)
			if err == nil && written != len(payload) {
				return io.ErrShortWrite
			}
			return err
		},
		release:  lease.ReleaseQueue,
		activate: lease.Activate,
		touch: func() {
			current.lastActivity.Store(time.Now().UnixNano())
		},
	}
	endpoint.associations[key] = current
	endpoint.waitGroup.Go(func() {
		handler(&current.association)
		endpoint.mutex.Lock()
		if endpoint.associations[key] == current {
			delete(endpoint.associations, key)
		}
		endpoint.mutex.Unlock()
		cancel()
		lease.Close()
	})
	return current, true
}

func (endpoint *Endpoint) sweep() {
	interval := endpoint.configuration.AssociationIdleTimeout / 2
	if interval > time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-endpoint.context.Done():
			return
		case now := <-ticker.C:
			cutoff := now.Add(-endpoint.configuration.AssociationIdleTimeout).UnixNano()
			endpoint.mutex.Lock()
			for _, association := range endpoint.associations {
				if association.lastActivity.Load() <= cutoff {
					association.cancel()
				}
			}
			endpoint.mutex.Unlock()
		}
	}
}

// Close releases the socket and cancels every association.
func (endpoint *Endpoint) Close() error {
	endpoint.mutex.Lock()
	if endpoint.closed {
		endpoint.mutex.Unlock()
		return nil
	}
	endpoint.closed = true
	endpoint.cancel()
	for _, association := range endpoint.associations {
		association.cancel()
	}
	endpoint.mutex.Unlock()
	err := endpoint.packet.Close()
	endpoint.waitGroup.Wait()
	return err
}

// Addr returns the bound client-side address.
func (endpoint *Endpoint) Addr() net.Addr {
	return endpoint.packet.LocalAddr()
}

// ForwardClient exchanges association datagrams with one authenticated stream.
func ForwardClient(
	ctx context.Context,
	stream net.Conn,
	packets <-chan []byte,
	releaseQueue func(int),
	writeResponse func([]byte) error,
	maxDatagram int,
	writeTimeout time.Duration,
) error {
	forwardContext, cancel := context.WithCancel(ctx)
	defer cancel()
	stopStream := context.AfterFunc(forwardContext, func() { stream.Close() })
	defer stopStream()
	results := make(chan error, 2)
	go func() {
		buffer := make([]byte, maxDatagram)
		for {
			payload, err := proxyudp.ReadDatagramInto(stream, buffer, maxDatagram)
			if err == nil {
				err = writeResponse(payload)
			}
			if err != nil {
				results <- err
				return
			}
		}
	}()
	go func() {
		writer := proxyudp.NewDatagramWriter(stream, maxDatagram)
		for {
			select {
			case payload, open := <-packets:
				if !open {
					results <- io.EOF
					return
				}
				releaseQueue(len(payload))
				if err := stream.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
					results <- err
					return
				}
				if err := writer.Write(payload); err != nil {
					results <- err
					return
				}
			case <-forwardContext.Done():
				results <- forwardContext.Err()
				return
			}
		}
	}()
	err := <-results
	cancel()
	_ = stream.Close()
	<-results
	return err
}

// TargetHandlerFactory connects an authenticated stream to one UDP target.
func TargetHandlerFactory(
	address string,
	maxDatagram int,
	writeTimeout time.Duration,
	authorize func() bool,
) link.StreamHandlerFactory {
	return func(ctx context.Context) (link.StreamHandler, func(), error) {
		if !authorize() {
			return nil, nil, errors.New("Forward target is no longer allowed")
		}
		target, err := (&net.Dialer{}).DialContext(ctx, "udp", address)
		if err != nil {
			return nil, nil, err
		}
		return func(ctx context.Context, _ string, stream net.Conn) error {
			return proxyudp.Forward(ctx, stream, target, maxDatagram, writeTimeout)
		}, func() { target.Close() }, nil
	}
}
