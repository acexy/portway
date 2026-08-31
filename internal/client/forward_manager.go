package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	forwardtcp "github.com/acexy/portway/internal/forward/tcp"
	forwardudp "github.com/acexy/portway/internal/forward/udp"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

type forwardRuntime struct {
	context       context.Context
	configuration config.ForwardConfig
	bindingID     string
	active        bool
	tcp           *forwardtcp.Listener
	udp           *forwardudp.Endpoint
	cancel        context.CancelFunc
}

type forwardManager struct {
	context   context.Context
	cancel    context.CancelFunc
	logger    *logging.Logger
	clientID  string
	sessionID string
	writer    *control.Writer
	transport transport.ClientSession
	mutex     sync.Mutex
	runtimes  map[string]*forwardRuntime
	offers    map[string]chan protocol.ForwardLinkOffer
	links     map[string]context.CancelFunc
	waitGroup sync.WaitGroup
	started   bool
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
		context: ctx, cancel: cancel, logger: logger,
		clientID: clientID, sessionID: sessionID,
		writer: writer, transport: transportSession,
		runtimes: make(map[string]*forwardRuntime),
		offers:   make(map[string]chan protocol.ForwardLinkOffer),
		links:    make(map[string]context.CancelFunc),
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
	packet, err := forwardudp.Listen(runtime.context, address, 8192, 64)
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
				manager.waitGroup.Go(func() { manager.serveTCP(&runtimeSnapshot, visitor) })
			})
			if err != nil && manager.context.Err() == nil && !errors.Is(err, net.ErrClosed) {
				manager.logger.Error("TCP Forward listener failed", err)
			}
		})
	}
	if runtimeSnapshot.udp != nil {
		manager.waitGroup.Go(func() {
			err := runtimeSnapshot.udp.Serve(func(association *forwardudp.Association) {
				manager.serveUDPAssociation(&runtimeSnapshot, association)
			})
			if err != nil && manager.context.Err() == nil && !errors.Is(err, net.ErrClosed) {
				manager.logger.Error("UDP Forward listener failed", err)
			}
		})
	}
}

func (manager *forwardManager) serveUDPAssociation(
	runtime *forwardRuntime,
	association *forwardudp.Association,
) {
	offer, err := manager.requestForwardOffer(association.Context, runtime)
	if err != nil {
		return
	}
	linkContext, cancelLink := context.WithCancel(association.Context)
	defer cancelLink()
	stream, err := manager.transport.OpenDataStream(linkContext)
	if err != nil {
		manager.reportForwardFailure(offer.LinkID, protocol.LinkErrorTransportFailed)
		return
	}
	defer stream.Close()
	if failure := manager.bindForwardStream(stream, offer); failure != "" {
		manager.reportForwardFailure(offer.LinkID, failure)
		return
	}
	_ = forwardudp.ForwardClient(
		association.Context, stream, association.Packets, association.Write, 8192, 3*time.Second,
	)
}

func (manager *forwardManager) serveTCP(runtime *forwardRuntime, visitor net.Conn) {
	defer visitor.Close()
	offer, err := manager.requestForwardOffer(runtime.context, runtime)
	if err != nil {
		return
	}
	manager.serveForwardStream(runtime, offer, func(linkContext context.Context, stream transport.Stream) {
		_ = forwardtcp.Forward(linkContext, visitor, stream)
	})
}

func (manager *forwardManager) requestForwardOffer(
	ctx context.Context,
	runtime *forwardRuntime,
) (protocol.ForwardLinkOffer, error) {
	requestID, err := newRequestID()
	if err != nil {
		return protocol.ForwardLinkOffer{}, err
	}
	offers := make(chan protocol.ForwardLinkOffer, 1)
	manager.mutex.Lock()
	manager.offers[requestID] = offers
	manager.mutex.Unlock()
	defer func() {
		manager.mutex.Lock()
		delete(manager.offers, requestID)
		manager.mutex.Unlock()
	}()
	if err := manager.writer.Write(protocol.MessageRequestForwardLink, protocol.RequestForwardLink{
		RequestID: requestID,
		Name:      runtime.configuration.Name,
		Type:      runtime.configuration.Type,
		BindingID: runtime.bindingID,
	}); err != nil {
		return protocol.ForwardLinkOffer{}, err
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	var offer protocol.ForwardLinkOffer
	select {
	case offer = <-offers:
	case <-timer.C:
		return protocol.ForwardLinkOffer{}, errors.New("Forward Link offer timed out")
	case <-ctx.Done():
		return protocol.ForwardLinkOffer{}, ctx.Err()
	}
	if offer.Error != nil || offer.LinkID == "" || offer.Ticket == "" ||
		offer.BindingID != runtime.bindingID || offer.Type != runtime.configuration.Type {
		return protocol.ForwardLinkOffer{}, errors.New("Forward Link offer was rejected")
	}
	return offer, nil
}

func (manager *forwardManager) serveForwardStream(
	runtime *forwardRuntime,
	offer protocol.ForwardLinkOffer,
	handler func(context.Context, transport.Stream),
) {
	linkContext, cancelLink := context.WithCancel(runtime.context)
	manager.mutex.Lock()
	manager.links[offer.LinkID] = cancelLink
	manager.mutex.Unlock()
	defer func() {
		cancelLink()
		manager.mutex.Lock()
		delete(manager.links, offer.LinkID)
		manager.mutex.Unlock()
	}()
	stream, err := manager.transport.OpenDataStream(linkContext)
	if err != nil {
		manager.reportForwardFailure(offer.LinkID, protocol.LinkErrorTransportFailed)
		return
	}
	defer stream.Close()
	if failure := manager.bindForwardStream(stream, offer); failure != "" {
		manager.reportForwardFailure(offer.LinkID, failure)
		return
	}
	handler(linkContext, stream)
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
	destination := manager.offers[offer.RequestID]
	manager.mutex.Unlock()
	if destination != nil {
		select {
		case destination <- offer:
		default:
		}
	}
}

func (manager *forwardManager) cancelLink(linkID string) {
	manager.mutex.Lock()
	cancel := manager.links[linkID]
	manager.mutex.Unlock()
	if cancel != nil {
		cancel()
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
	for _, cancel := range manager.links {
		cancel()
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
