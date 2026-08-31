// Package udp implements UDP Forward endpoints, associations, and target runtime behavior.
package udp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/acexy/portway/internal/link"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
)

// Association owns queued datagrams for one local visitor address.
type Association struct {
	Context context.Context
	Packets <-chan []byte
	write   func([]byte) error
}

// Write sends one response datagram to the association visitor.
func (association *Association) Write(payload []byte) error {
	return association.write(payload)
}

type associationRuntime struct {
	association Association
	cancel      context.CancelFunc
	queue       chan []byte
}

// Endpoint owns one client-side UDP socket and its visitor associations.
type Endpoint struct {
	context      context.Context
	packet       net.PacketConn
	maxDatagram  int
	queueSize    int
	mutex        sync.Mutex
	associations map[string]*associationRuntime
	waitGroup    sync.WaitGroup
	closed       bool
}

// Listen prepares one UDP Forward endpoint.
func Listen(
	ctx context.Context,
	address string,
	maxDatagram int,
	queueSize int,
) (*Endpoint, error) {
	packet, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	return &Endpoint{
		context: ctx, packet: packet, maxDatagram: maxDatagram, queueSize: queueSize,
		associations: make(map[string]*associationRuntime),
	}, nil
}

// Serve routes local datagrams into source-address associations.
func (endpoint *Endpoint) Serve(handler func(*Association)) error {
	buffer := make([]byte, endpoint.maxDatagram+1)
	for {
		length, address, err := endpoint.packet.ReadFrom(buffer)
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
		payload := append([]byte(nil), buffer[:length]...)
		select {
		case association.queue <- payload:
		default:
		}
	}
}

func (endpoint *Endpoint) association(
	address net.Addr,
	handler func(*Association),
) (*associationRuntime, bool) {
	key := address.String()
	endpoint.mutex.Lock()
	defer endpoint.mutex.Unlock()
	if endpoint.closed {
		return nil, false
	}
	if current := endpoint.associations[key]; current != nil {
		return current, true
	}
	ctx, cancel := context.WithCancel(endpoint.context)
	queue := make(chan []byte, endpoint.queueSize)
	current := &associationRuntime{cancel: cancel, queue: queue}
	current.association = Association{
		Context: ctx,
		Packets: queue,
		write: func(payload []byte) error {
			written, err := endpoint.packet.WriteTo(payload, address)
			if err == nil && written != len(payload) {
				return io.ErrShortWrite
			}
			return err
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
	})
	return current, true
}

// Close releases the socket and cancels every association.
func (endpoint *Endpoint) Close() error {
	endpoint.mutex.Lock()
	if endpoint.closed {
		endpoint.mutex.Unlock()
		return nil
	}
	endpoint.closed = true
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
	writeResponse func([]byte) error,
	maxDatagram int,
	writeTimeout time.Duration,
) error {
	forwardContext, cancel := context.WithCancel(ctx)
	defer cancel()
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
		for {
			select {
			case payload := <-packets:
				if err := stream.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
					results <- err
					return
				}
				if err := proxyudp.WriteDatagram(stream, payload, maxDatagram); err != nil {
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
	return func(_ context.Context) (link.StreamHandler, error) {
		if !authorize() {
			return nil, errors.New("Forward target is no longer allowed")
		}
		target, err := net.Dial("udp", address)
		if err != nil {
			return nil, err
		}
		return func(ctx context.Context, _ string, stream net.Conn) error {
			return proxyudp.Forward(ctx, stream, target, maxDatagram, writeTimeout)
		}, nil
	}
}
