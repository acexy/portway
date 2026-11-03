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
	context         context.Context
	cancel          context.CancelFunc
	configuration   config.UDPConfig
	endpoint        *Endpoint
	broker          *link.Broker
	limiter         *Limiter
	filter          *ipfilter.Filter
	resolveTarget   TargetResolver
	mutex           sync.Mutex
	associations    map[netip.AddrPort]*association
	closeOnce       sync.Once
	waitGroup       sync.WaitGroup
	responseEnabled atomic.Bool
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
	binding.responseEnabled.Store(true)
	binding.waitGroup.Go(binding.sweep)
	return binding
}

// SetResponseEnabled controls whether association responses reach the visitor.
func (binding *Binding) SetResponseEnabled(enabled bool) {
	binding.responseEnabled.Store(enabled)
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
		binding.recordRejection()
		binding.mutex.Unlock()
		return
	}
	target.MaxDatagramSize = binding.configuration.MaxDatagramSize
	target.WriteTimeout = binding.configuration.LinkWriteTimeout
	lease, allowed := binding.limiter.Acquire(
		target.ClientID,
		target.BindingName,
		source.Addr(),
		time.Now(),
	)
	if !allowed {
		binding.recordRejection()
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
		binding.recordRejection()
		binding.mutex.Unlock()
		association.cancel()
		lease.Close()
		return
	}
	association.releaseSource = releaseSource
	binding.waitGroup.Add(1)
	binding.associations[source] = association
	if association.traffic != nil {
		association.traffic.created.Add(1)
	}
	binding.mutex.Unlock()

	if !association.enqueue(payload) {
		association.Close()
		association.complete(true)
		association.finish()
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

func (binding *Binding) recordRejection() {
	if binding.endpoint != nil {
		binding.endpoint.traffic.rejected.Add(1)
	}
}

func (binding *Binding) sweep() {
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
			cutoff := now.Add(-binding.configuration.AssociationIdleTimeout)
			binding.mutex.Lock()
			candidates := coll.MapValues(binding.associations)
			binding.mutex.Unlock()
			for _, candidate := range candidates {
				candidate.closeIfIdle(cutoff)
			}
		}
	}
}

// Suspend closes the current association generation while preserving the
// Binding runtime for an original control connection to reactivate.
func (binding *Binding) Suspend() {
	binding.mutex.Lock()
	associations := coll.MapValues(binding.associations)
	binding.mutex.Unlock()
	for _, candidate := range associations {
		candidate.Close()
	}
	for _, candidate := range associations {
		<-candidate.done
	}
}

// Close permanently releases every association and background task owned by
// this binding.
func (binding *Binding) Close() {
	binding.closeOnce.Do(func() {
		binding.cancel()
		binding.Suspend()
	})
	binding.waitGroup.Wait()
}

type association struct {
	traffic         *trafficCounters
	binding         *Binding
	source          netip.AddrPort
	target          link.Target
	lease           *AssociationLease
	context         context.Context
	cancel          context.CancelFunc
	queue           chan []byte
	activityMutex   sync.Mutex
	lastActivity    time.Time
	closing         bool
	releaseSource   func()
	closeOnce       sync.Once
	finishOnce      sync.Once
	completionMutex sync.Mutex
	startFinished   bool
	forwardFinished bool
	done            chan struct{}
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
	if binding.endpoint != nil {
		candidate.traffic = &binding.endpoint.traffic
	}
	return candidate
}

func (association *association) enqueue(payload []byte) bool {
	if len(association.queue) == cap(association.queue) || !association.lease.ReserveQueue(len(payload)) {
		if association.traffic != nil {
			association.traffic.queueDropped.Add(1)
		}
		return false
	}
	payload = append([]byte(nil), payload...)
	select {
	case association.queue <- payload:
		association.touch()
		return true
	default:
		association.lease.ReleaseQueue(len(payload))
		if association.traffic != nil {
			association.traffic.queueDropped.Add(1)
		}
		return false
	}
}

func (association *association) start() {
	defer association.complete(true)
	err := association.binding.broker.ServeStreamContext(
		association.context,
		association.target,
		func(string) {
			association.Close()
			association.finish()
		},
		func(ctx context.Context, _ string, stream net.Conn) error {
			return association.forward(ctx, stream)
		},
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
		association.cancel()
		stream.Close()
	})
	defer stopBroker()
	defer association.Close()

	writeErrors := make(chan error, 1)
	writerDone := make(chan struct{})
	defer func() {
		association.cancel()
		_ = stream.Close()
		<-writerDone
	}()
	go func() {
		defer close(writerDone)
		frameBuffer := make([]byte, frameHeaderSize+association.binding.configuration.MaxDatagramSize)
		fail := func(err error) {
			association.recordWriteTimeout(err)
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
				if err := writeDatagramBuffer(
					stream,
					payload,
					association.binding.configuration.MaxDatagramSize,
					frameBuffer,
				); err != nil {
					fail(err)
					return
				}
				association.touch()
				if association.traffic != nil {
					association.traffic.uplinkDatagrams.Add(1)
					association.traffic.uplinkBytes.Add(uint64(len(payload)))
				}
			}
		}
	}()

	responseBuffer := make([]byte, association.binding.configuration.MaxDatagramSize)
	for {
		payload, err := ReadDatagramInto(
			stream,
			responseBuffer,
			association.binding.configuration.MaxDatagramSize,
		)
		if err != nil {
			return errors.Join(err, receiveWriteError(writeErrors))
		}
		if association.traffic != nil {
			association.traffic.downlinkDatagrams.Add(1)
			association.traffic.downlinkBytes.Add(uint64(len(payload)))
		}
		if association.binding.responseEnabled.Load() {
			if err := association.binding.endpoint.WriteTo(association.context, payload, association.source, association.binding.configuration.LinkWriteTimeout); err != nil {
				association.recordWriteTimeout(err)
				return err
			}
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
	association.complete(false)
}

// A pending cancellation can arrive while the open_link write is still in
// progress. Neither task may release the shared lease on the other's behalf.
func (association *association) complete(start bool) {
	association.completionMutex.Lock()
	if start {
		association.startFinished = true
	} else {
		association.forwardFinished = true
	}
	finished := association.startFinished && association.forwardFinished
	association.completionMutex.Unlock()
	if !finished {
		return
	}
	association.finishOnce.Do(func() {
		association.lease.Close()
		close(association.done)
		association.binding.waitGroup.Done()
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
	association.activityMutex.Lock()
	if !association.closing {
		association.lastActivity = time.Now()
	}
	association.activityMutex.Unlock()
}

func (association *association) recordWriteTimeout(err error) {
	var networkError net.Error
	if association.traffic != nil && (errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &networkError) && networkError.Timeout())) {
		association.traffic.writeTimeouts.Add(1)
	}
}

func (association *association) closeIfIdle(cutoff time.Time) {
	association.activityMutex.Lock()
	if association.closing || association.lastActivity.After(cutoff) {
		association.activityMutex.Unlock()
		return
	}
	association.closing = true
	association.activityMutex.Unlock()
	if association.traffic != nil {
		association.traffic.expired.Add(1)
	}
	association.Close()
}

// Close releases one association exactly once.
func (association *association) Close() {
	association.closeOnce.Do(func() {
		association.activityMutex.Lock()
		association.closing = true
		association.activityMutex.Unlock()
		association.cancel()
		association.binding.remove(association)
		association.releaseSource()
	})
}
