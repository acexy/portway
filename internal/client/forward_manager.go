package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	forwardtcp "github.com/acexy/portway/internal/forward/tcp"
	forwardudp "github.com/acexy/portway/internal/forward/udp"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
	"github.com/acexy/portway/internal/transport"
)

const forwardLinkOfferTimeout = 10 * time.Second

type forwardOfferRequest struct {
	context   context.Context
	runtime   *forwardRuntime
	ready     chan protocol.ForwardLinkOffer
	link      *forwardLink
	delivered bool
}

type forwardLink struct {
	context context.Context
	cancel  context.CancelFunc
	offer   protocol.ForwardLinkOffer
}

type forwardRuntime struct {
	context       context.Context
	configuration config.ForwardConfig
	bindingID     string
	active        bool
	udpConfig     config.UDPConfig
	tcp           *forwardtcp.Listener
	udp           *forwardudp.Endpoint
	cancel        context.CancelFunc
}

type forwardManager struct {
	context     context.Context
	cancel      context.CancelFunc
	logger      *logging.Logger
	clientID    string
	sessionID   string
	writer      *control.Writer
	transport   transport.ClientSession
	mutex       sync.Mutex
	runtimes    map[string]*forwardRuntime
	offers      map[string]*forwardOfferRequest
	links       map[string]*forwardLink
	tcpCapacity forwardCapacity
	waitGroup   sync.WaitGroup
	udpConfig   config.UDPConfig
	udpLimiter  *proxyudp.Limiter
	started     bool
}

func newForwardManager(
	parent context.Context,
	logger *logging.Logger,
	clientID string,
	sessionID string,
	writer *control.Writer,
	transportSession transport.ClientSession,
	configurations []config.ForwardConfig,
) (*forwardManager, error) {
	ctx, cancel := context.WithCancel(parent)
	manager := &forwardManager{
		context: ctx, cancel: cancel, logger: logger.WithComponent("forward"),
		clientID: clientID, sessionID: sessionID,
		writer: writer, transport: transportSession,
		runtimes: make(map[string]*forwardRuntime),
		offers:   make(map[string]*forwardOfferRequest),
		links:    make(map[string]*forwardLink),
	}
	for _, configuration := range configurations {
		runtimeContext, runtimeCancel := context.WithCancel(ctx)
		runtime := &forwardRuntime{
			context: runtimeContext, configuration: configuration, cancel: runtimeCancel,
		}
		manager.runtimes[configuration.Name] = runtime
	}
	return manager, nil
}

func (manager *forwardManager) applyBindings(results []protocol.ForwardResult) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if len(results) != len(manager.runtimes) {
		return errors.New("Forward binding result count does not match local configuration")
	}
	for _, result := range results {
		runtime := manager.runtimes[result.Name]
		if runtime == nil || runtime.configuration.Type != result.Type || result.BindingID == "" {
			return errors.New("Forward binding result does not match local configuration")
		}
		if result.Type == protocol.ForwardTypeUDP {
			if result.UDP == nil {
				return errors.New("UDP Forward binding result is missing runtime limits")
			}
			udpConfiguration := forwardUDPConfig(*result.UDP)
			if err := config.ValidateUDPConfig(udpConfiguration); err != nil {
				return fmt.Errorf("invalid UDP Forward runtime limits: %w", err)
			}
			manager.applyUDPConfig(runtime, udpConfiguration)
		}
		runtime.bindingID = result.BindingID
		runtime.active = result.Active
	}
	return nil
}

func (manager *forwardManager) start() error {
	manager.mutex.Lock()
	manager.started = true
	runtimes := make([]*forwardRuntime, 0, len(manager.runtimes))
	for _, runtime := range manager.runtimes {
		if runtime.active {
			if err := manager.prepareRuntime(runtime); err != nil {
				manager.mutex.Unlock()
				return err
			}
			runtimes = append(runtimes, runtime)
		} else {
			manager.logger.InfoWithFields("Forward disabled by server policy", map[string]any{
				"event": "forward_disabled", "forward_name": runtime.configuration.Name,
			})
		}
	}
	manager.mutex.Unlock()
	for _, runtime := range runtimes {
		manager.serveRuntime(runtime)
	}
	return nil
}

func (manager *forwardManager) prepareRuntime(runtime *forwardRuntime) error {
	address := net.JoinHostPort(runtime.configuration.Listen.IP, fmt.Sprint(runtime.configuration.Listen.Port))
	if runtime.configuration.Type == protocol.ForwardTypeTCP {
		listener, err := forwardtcp.Listen(runtime.context, address)
		if err != nil {
			return fmt.Errorf("prepare TCP Forward %q: %w", runtime.configuration.Name, err)
		}
		runtime.tcp = listener
		return nil
	}
	packet, err := forwardudp.Listen(
		runtime.context, address, manager.clientID, runtime.configuration.Name, runtime.udpConfig,
		manager.udpLimiter,
	)
	if err != nil {
		return fmt.Errorf("prepare UDP Forward %q: %w", runtime.configuration.Name, err)
	}
	runtime.udp = packet
	return nil
}

func (manager *forwardManager) serveRuntime(runtime *forwardRuntime) {
	runtimeSnapshot := *runtime
	if runtimeSnapshot.tcp != nil {
		manager.waitGroup.Go(func() {
			err := runtimeSnapshot.tcp.Serve(func(visitor net.Conn) {
				lease := manager.tcpCapacity.acquire(runtimeSnapshot.configuration.Name)
				if lease == nil {
					visitor.Close()
					return
				}
				manager.waitGroup.Go(func() {
					defer lease.close()
					manager.serveTCP(&runtimeSnapshot, visitor, lease)
				})
			})
			if err != nil && manager.context.Err() == nil && !errors.Is(err, net.ErrClosed) {
				manager.logger.WithFields(map[string]any{
					"event": "forward_listener_failed", "forward_name": runtimeSnapshot.configuration.Name,
				}).Error("TCP Forward listener failed", err)
			}
		})
	}
	if runtimeSnapshot.udp != nil {
		manager.waitGroup.Go(func() {
			err := runtimeSnapshot.udp.Serve(func(association *forwardudp.Association) {
				manager.serveUDPAssociation(&runtimeSnapshot, association)
			})
			if err != nil && manager.context.Err() == nil && !errors.Is(err, net.ErrClosed) {
				manager.logger.WithFields(map[string]any{
					"event": "forward_listener_failed", "forward_name": runtimeSnapshot.configuration.Name,
				}).Error("UDP Forward listener failed", err)
			}
		})
	}
}

func (manager *forwardManager) serveUDPAssociation(
	runtime *forwardRuntime,
	association *forwardudp.Association,
) {
	link, err := manager.requestForwardOffer(association.Context, runtime)
	if err != nil {
		return
	}
	manager.serveForwardStream(link, func(ctx context.Context, stream transport.Stream) {
		association.Activate()
		_ = forwardudp.ForwardClient(
			ctx, stream, association.Packets, association.ReleaseQueue,
			association.Write, runtime.udpConfig.MaxDatagramSize, runtime.udpConfig.LinkWriteTimeout,
		)
	})
}

func (manager *forwardManager) serveTCP(runtime *forwardRuntime, visitor net.Conn, lease *forwardLease) {
	defer visitor.Close()
	stopVisitor := context.AfterFunc(runtime.context, func() { visitor.Close() })
	defer stopVisitor()
	link, err := manager.requestForwardOffer(runtime.context, runtime)
	if err != nil {
		return
	}
	stopLinkVisitor := context.AfterFunc(link.context, func() { visitor.Close() })
	defer stopLinkVisitor()
	manager.serveForwardStream(link, func(linkContext context.Context, stream transport.Stream) {
		lease.activate()
		_ = forwardtcp.Forward(linkContext, visitor, stream)
	})
}

func (manager *forwardManager) requestForwardOffer(
	ctx context.Context,
	runtime *forwardRuntime,
) (*forwardLink, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	requestID, err := newRequestID()
	if err != nil {
		return nil, err
	}
	offers := make(chan protocol.ForwardLinkOffer, 1)
	request := &forwardOfferRequest{context: ctx, runtime: runtime, ready: offers}
	manager.mutex.Lock()
	if len(manager.offers) >= maxForwardPending || manager.context.Err() != nil {
		manager.mutex.Unlock()
		return nil, errors.New("Forward offer capacity reached or manager closed")
	}
	manager.offers[requestID] = request
	manager.mutex.Unlock()
	accepted := false
	defer func() {
		manager.mutex.Lock()
		delete(manager.offers, requestID)
		link := request.link
		manager.mutex.Unlock()
		if !accepted && link != nil {
			manager.releaseForwardLink(link)
			manager.cancelForwardOffer(link.offer.LinkID)
		}
	}()
	if err := manager.writer.Write(protocol.MessageRequestForwardLink, protocol.RequestForwardLink{
		RequestID: requestID,
		Name:      runtime.configuration.Name,
		Type:      runtime.configuration.Type,
		BindingID: runtime.bindingID,
	}); err != nil {
		return nil, err
	}
	timer := time.NewTimer(forwardLinkOfferTimeout)
	defer timer.Stop()
	var offer protocol.ForwardLinkOffer
	select {
	case offer = <-offers:
	case <-timer.C:
		return nil, errors.New("Forward Link offer timed out")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if offer.Error != nil || request.link == nil {
		return nil, errors.New("Forward Link offer was rejected")
	}
	accepted = true
	return request.link, nil
}

func (manager *forwardManager) serveForwardStream(
	link *forwardLink,
	handler func(context.Context, transport.Stream),
) {
	defer manager.releaseForwardLink(link)
	offer := link.offer
	// Stop expiry after Bind; active streams retain their normal lifetime.
	timer := time.AfterFunc(time.Until(time.UnixMilli(offer.ExpiresAtUnixMS)), link.cancel)
	defer timer.Stop()
	if link.context.Err() != nil {
		manager.cancelForwardOffer(offer.LinkID)
		return
	}
	stream, err := manager.transport.OpenDataStream(link.context)
	if err != nil {
		manager.reportForwardFailure(offer.LinkID, protocol.LinkErrorTransportFailed)
		return
	}
	defer stream.Close()
	stopStream := context.AfterFunc(link.context, func() { stream.Close() })
	defer stopStream()
	if failure := manager.bindForwardStream(stream, offer); failure != "" {
		manager.reportForwardFailure(offer.LinkID, failure)
		return
	}
	if !timer.Stop() || link.context.Err() != nil {
		manager.cancelForwardOffer(offer.LinkID)
		return
	}
	handler(link.context, stream)
}

func (manager *forwardManager) releaseForwardLink(link *forwardLink) {
	link.cancel()
	manager.mutex.Lock()
	if manager.links[link.offer.LinkID] == link {
		delete(manager.links, link.offer.LinkID)
	}
	manager.mutex.Unlock()
}

func (manager *forwardManager) cancelForwardOffer(linkID string) {
	_ = manager.writer.Write(protocol.MessageCancelForwardLink, protocol.CancelForwardLink{LinkID: linkID})
}

func (manager *forwardManager) bindForwardStream(
	stream transport.Stream,
	offer protocol.ForwardLinkOffer,
) protocol.LinkErrorCode {
	if err := stream.SetDeadline(time.Now().Add(dataBindTimeout)); err != nil {
		return protocol.LinkErrorTransportFailed
	}
	if err := protocol.WriteControl(stream, protocol.MessageBindLink, protocol.BindLink{
		ClientID:  manager.clientID,
		SessionID: manager.sessionID,
		LinkID:    offer.LinkID,
		ProxyType: protocol.ProxyType(offer.Type),
		BindingID: offer.BindingID,
		Ticket:    offer.Ticket,
		Direction: protocol.LinkDirectionForward,
	}); err != nil {
		return protocol.LinkErrorTransportFailed
	}
	envelope, err := protocol.ReadControl(stream)
	if err != nil || envelope.Type != protocol.MessageBindResult {
		return protocol.LinkErrorTransportFailed
	}
	var result protocol.BindResult
	if err := protocol.DecodePayload(envelope, &result); err != nil || result.LinkID != offer.LinkID {
		return protocol.LinkErrorInvalidBinding
	}
	if result.Status != protocol.LinkStatusAccepted {
		if result.Error != nil {
			return *result.Error
		}
		return protocol.LinkErrorInvalidBinding
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		return protocol.LinkErrorTransportFailed
	}
	return ""
}

func (manager *forwardManager) deliverOffer(offer protocol.ForwardLinkOffer) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	request := manager.offers[offer.RequestID]
	if request != nil && !request.delivered {
		request.delivered = true
		if offer.Error == nil && offer.LinkID != "" && offer.Ticket != "" &&
			offer.BindingID == request.runtime.bindingID && offer.Type == request.runtime.configuration.Type &&
			offer.Name == request.runtime.configuration.Name && offer.ExpiresAtUnixMS > time.Now().UnixMilli() {
			if _, exists := manager.links[offer.LinkID]; exists {
				return
			}
			ctx, cancel := context.WithCancel(request.context)
			request.link = &forwardLink{context: ctx, cancel: cancel, offer: offer}
			manager.links[offer.LinkID] = request.link
		}
		select {
		case request.ready <- offer:
		default:
		}
	}
}

func (manager *forwardManager) cancelLink(linkID string) {
	manager.mutex.Lock()
	link := manager.links[linkID]
	manager.mutex.Unlock()
	if link != nil {
		link.cancel()
	}
}

func (manager *forwardManager) revoke(revocation protocol.ForwardBindingRevoked) {
	manager.mutex.Lock()
	runtime := manager.runtimes[revocation.Name]
	matched := runtime != nil && runtime.bindingID == revocation.BindingID
	if matched {
		runtime.active = false
		runtime.bindingID = ""
	}
	manager.mutex.Unlock()
	if matched {
		runtime.cancel()
		if runtime.tcp != nil {
			runtime.tcp.Close()
		}
		if runtime.udp != nil {
			runtime.udp.Close()
		}
		runtime.tcp = nil
		runtime.udp = nil
		manager.logger.InfoWithFields("Forward disabled by server policy", map[string]any{
			"event": "forward_disabled", "forward_name": revocation.Name,
			"generation": revocation.Generation, "reason": revocation.Reason,
		})
	}
}

func (manager *forwardManager) activate(activation protocol.ForwardBindingActivated) error {
	manager.mutex.Lock()
	runtime := manager.runtimes[activation.Name]
	if runtime == nil || runtime.configuration.Type != activation.Type || activation.BindingID == "" {
		manager.mutex.Unlock()
		return errors.New("Forward activation does not match local configuration")
	}
	if activation.Type == protocol.ForwardTypeUDP {
		if activation.UDP == nil {
			manager.mutex.Unlock()
			return errors.New("UDP Forward activation is missing runtime limits")
		}
		udpConfiguration := forwardUDPConfig(*activation.UDP)
		if err := config.ValidateUDPConfig(udpConfiguration); err != nil {
			manager.mutex.Unlock()
			return fmt.Errorf("invalid UDP Forward runtime limits: %w", err)
		}
		manager.applyUDPConfig(runtime, udpConfiguration)
	}
	if runtime.active && runtime.bindingID == activation.BindingID {
		manager.mutex.Unlock()
		return nil
	}
	runtime.context, runtime.cancel = context.WithCancel(manager.context)
	runtime.bindingID = activation.BindingID
	runtime.active = true
	if err := manager.prepareRuntime(runtime); err != nil {
		runtime.active = false
		runtime.bindingID = ""
		manager.mutex.Unlock()
		return err
	}
	started := manager.started
	manager.mutex.Unlock()
	if started {
		manager.serveRuntime(runtime)
	}
	manager.logger.InfoWithFields("Forward enabled by server policy", map[string]any{
		"event": "forward_enabled", "forward_name": activation.Name,
		"generation": activation.Generation,
	})
	return nil
}

func (manager *forwardManager) applyUDPConfig(
	runtime *forwardRuntime,
	configuration config.UDPConfig,
) {
	if manager.udpLimiter == nil || !reflect.DeepEqual(manager.udpConfig, configuration) {
		manager.udpConfig = configuration
		manager.udpLimiter = proxyudp.NewLimiter(configuration)
	}
	runtime.udpConfig = configuration
}

func forwardUDPConfig(configuration protocol.ForwardUDPConfig) config.UDPConfig {
	return config.UDPConfig{
		AssociationIdleTimeout:               configuration.AssociationIdleTimeout,
		LinkWriteTimeout:                     configuration.LinkWriteTimeout,
		MaxDatagramSize:                      configuration.MaxDatagramSize,
		MaxAssociations:                      configuration.MaxAssociations,
		MaxAssociationsPerClient:             configuration.MaxAssociationsPerClient,
		MaxAssociationsPerProxy:              configuration.MaxAssociationsPerForward,
		MaxAssociationsPerSourceIP:           configuration.MaxAssociationsPerSourceIP,
		MaxPendingAssociations:               configuration.MaxPendingAssociations,
		MaxPendingAssociationsPerClient:      configuration.MaxPendingAssociationsPerClient,
		MaxPendingAssociationsPerProxy:       configuration.MaxPendingAssociationsPerForward,
		MaxNewAssociationsPerSecond:          configuration.MaxNewAssociationsPerSecond,
		MaxNewAssociationsPerSecondPerClient: configuration.MaxNewAssociationsPerSecondPerClient,
		MaxNewAssociationsPerSecondPerProxy:  configuration.MaxNewAssociationsPerSecondPerForward,
		MaxQueuedDatagramsPerAssociation:     configuration.MaxQueuedDatagramsPerAssociation,
		MaxQueuedBytesPerAssociation:         configuration.MaxQueuedBytesPerAssociation,
		MaxQueuedBytes:                       configuration.MaxQueuedBytes,
	}
}

func (manager *forwardManager) reportForwardFailure(linkID string, code protocol.LinkErrorCode) {
	_ = manager.writer.Write(protocol.MessageForwardLinkFailed, protocol.ForwardLinkFailed{
		LinkID: linkID,
		Code:   code,
	})
}

func (manager *forwardManager) close() {
	manager.cancel()
	manager.mutex.Lock()
	runtimes := make([]*forwardRuntime, 0, len(manager.runtimes))
	for _, runtime := range manager.runtimes {
		runtimes = append(runtimes, runtime)
	}
	for _, link := range manager.links {
		link.cancel()
	}
	manager.mutex.Unlock()
	for _, runtime := range runtimes {
		runtime.cancel()
		if runtime.tcp != nil {
			runtime.tcp.Close()
		}
		if runtime.udp != nil {
			runtime.udp.Close()
		}
	}
	manager.waitGroup.Wait()
}
