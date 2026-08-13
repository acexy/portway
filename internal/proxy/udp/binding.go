package udp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/security/ipfilter"
)

// TargetResolver resolves the current authenticated owner of a UDP binding.
type TargetResolver func() (link.Target, error)

// Binding owns all associations for one registered UDP proxy.
type Binding struct {
	context       context.Context
	cancel        context.CancelFunc
	configuration config.UDPConfig
	endpoint      *Endpoint
	broker        *link.Broker
	limiter       *Limiter
	filter        *ipfilter.Filter
	resolveTarget TargetResolver
	mutex         sync.Mutex
	associations  map[netip.AddrPort]*association
	closeOnce     sync.Once
	waitGroup     sync.WaitGroup
}

// NewBinding creates a UDP runtime without changing the endpoint handler.
func NewBinding(
	parent context.Context,
	configuration config.UDPConfig,
	endpoint *Endpoint,
	broker *link.Broker,
	limiter *Limiter,
	filter *ipfilter.Filter,
	resolveTarget TargetResolver,
) *Binding {
	ctx, cancel := context.WithCancel(parent)
	binding := &Binding{
		context:       ctx,
		cancel:        cancel,
		configuration: configuration,
		endpoint:      endpoint,
		broker:        broker,
		limiter:       limiter,
		filter:        filter,
		resolveTarget: resolveTarget,
		associations:  make(map[netip.AddrPort]*association),
	}
	binding.waitGroup.Add(1)
	go binding.sweep()
	return binding
}

// HandleDatagram routes one public datagram to its association.
func (binding *Binding) HandleDatagram(source netip.AddrPort, payload []byte) {
	binding.mutex.Lock()
	if binding.context.Err() != nil {
		binding.mutex.Unlock()
		return
	}
	if existing := binding.associations[source]; existing != nil {
		binding.mutex.Unlock()
		existing.enqueue(payload)
		return
	}
	target, err := binding.resolveTarget()
	if err != nil {
		binding.mutex.Unlock()
		return
	}
	target.MaxDatagramSize = binding.configuration.MaxDatagramSize
	target.WriteTimeout = binding.configuration.LinkWriteTimeout
	lease, allowed := binding.limiter.Acquire(
		target.ClientID,
		target.ProxyName,
		source.Addr(),
		time.Now(),
	)
	if !allowed {
		binding.mutex.Unlock()
		return
	}
	association := newAssociation(binding, source, target, lease)
	releaseSource, sourceAllowed := func() (func(), bool) {
		if binding.filter == nil {
			return func() {}, true
		}
		return binding.filter.RegisterFor(source.Addr(), "udp_proxy", association.Close)
	}()
	if !sourceAllowed {
		binding.mutex.Unlock()
		lease.Close()
		return
	}
	association.releaseSource = releaseSource
	binding.associations[source] = association
	binding.mutex.Unlock()

	if !association.enqueue(payload) {
		association.Close()
		return
	}
	go association.start()
}

func (binding *Binding) remove(candidate *association) {
	binding.mutex.Lock()
	if binding.associations[candidate.source] == candidate {
		delete(binding.associations, candidate.source)
	}
	binding.mutex.Unlock()
}

func (binding *Binding) sweep() {
	defer binding.waitGroup.Done()
	interval := binding.configuration.AssociationIdleTimeout / 2
	if interval > time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-binding.context.Done():
			return
		case now := <-ticker.C:
			cutoff := now.Add(-binding.configuration.AssociationIdleTimeout).UnixNano()
			binding.mutex.Lock()
			expired := coll.MapFilterToSlice(binding.associations, func(_ netip.AddrPort, candidate *association) (*association, bool) {
				return candidate, candidate.lastActivity.Load() <= cutoff
			})
			binding.mutex.Unlock()
			for _, candidate := range expired {
				candidate.Close()
			}
		}
	}
}

// Close releases every association owned by this binding.
func (binding *Binding) Close() {
	binding.closeOnce.Do(func() {
		binding.cancel()
		binding.mutex.Lock()
		associations := coll.MapValues(binding.associations)
		binding.mutex.Unlock()
		for _, candidate := range associations {
			candidate.Close()
		}
		for _, candidate := range associations {
			<-candidate.done
		}
	})
	binding.waitGroup.Wait()
}

type association struct {
	binding       *Binding
	source        netip.AddrPort
	target        link.Target
	lease         *AssociationLease
	context       context.Context
	cancel        context.CancelFunc
	queue         chan []byte
	lastActivity  atomic.Int64
	releaseSource func()
	closeOnce     sync.Once
	finishOnce    sync.Once
	done          chan struct{}
}

func newAssociation(
	binding *Binding,
	source netip.AddrPort,
	target link.Target,
	lease *AssociationLease,
) *association {
	ctx, cancel := context.WithCancel(binding.context)
	candidate := &association{
		binding:       binding,
		source:        source,
		target:        target,
		lease:         lease,
		context:       ctx,
		cancel:        cancel,
		queue:         make(chan []byte, binding.configuration.MaxQueuedDatagramsPerAssociation),
		releaseSource: func() {},
		done:          make(chan struct{}),
	}
	candidate.touch()
	return candidate
}

func (association *association) enqueue(payload []byte) bool {
	if !association.lease.ReserveQueue(len(payload)) {
		return false
	}
	select {
	case association.queue <- payload:
		association.touch()
		return true
	default:
		association.lease.ReleaseQueue(len(payload))
		return false
	}
}

func (association *association) start() {
	err := association.binding.broker.ServeStreamContext(
		association.context,
		association.target,
		func() {
			association.Close()
			association.finish()
		},
		association.forward,
	)
	if err != nil {
		association.Close()
		association.finish()
	}
}

func (association *association) forward(
	brokerContext context.Context,
	stream net.Conn,
) error {
	defer association.finish()
	association.lease.Activate()
	stopAssociation := context.AfterFunc(association.context, func() {
		stream.Close()
	})
	defer stopAssociation()
	stopBroker := context.AfterFunc(brokerContext, func() {
		stream.Close()
	})
	defer stopBroker()
	defer association.Close()

	writeErrors := make(chan error, 1)
	go func() {
		fail := func(err error) {
			writeErrors <- err
			stream.Close()
		}
		for {
			select {
			case <-association.context.Done():
				fail(association.context.Err())
				return
			case payload := <-association.queue:
				association.lease.ReleaseQueue(len(payload))
				if err := stream.SetWriteDeadline(
					time.Now().Add(association.binding.configuration.LinkWriteTimeout),
				); err != nil {
					fail(err)
					return
				}
				if err := WriteDatagram(
					stream,
					payload,
					association.binding.configuration.MaxDatagramSize,
				); err != nil {
					fail(err)
					return
				}
				association.touch()
			}
		}
	}()

	for {
		payload, err := ReadDatagram(
			stream,
			association.binding.configuration.MaxDatagramSize,
		)
		if err != nil {
			return errors.Join(err, receiveWriteError(writeErrors))
		}
		if err := association.binding.endpoint.WriteTo(payload, association.source); err != nil {
			return err
		}
		association.touch()
		select {
		case err := <-writeErrors:
			return err
		default:
		}
	}
}

func (association *association) finish() {
	association.finishOnce.Do(func() {
		close(association.done)
	})
}

func receiveWriteError(errors <-chan error) error {
	select {
	case err := <-errors:
		return err
	default:
		return nil
	}
}

func (association *association) touch() {
	association.lastActivity.Store(time.Now().UnixNano())
}

// Close releases one association exactly once.
func (association *association) Close() {
	association.closeOnce.Do(func() {
		association.cancel()
		association.binding.remove(association)
		association.releaseSource()
		association.lease.Close()
	})
}
