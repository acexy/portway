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
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
	"github.com/acexy/portway/internal/transport"
)

type forwardRuntime struct {
	configuration config.ForwardConfig
	bindingID     string
	listener      net.Listener
	packet        net.PacketConn
	associations  map[string]*udpForwardAssociation
	cancel        context.CancelFunc
}

type udpForwardAssociation struct {
	address net.Addr
	queue   chan []byte
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
		runtime := &forwardRuntime{configuration: configuration, cancel: runtimeCancel}
		if configuration.Type == protocol.ForwardTypeTCP {
			address := net.JoinHostPort(configuration.ListenIP, fmt.Sprint(configuration.ListenPort))
			listener, err := (&net.ListenConfig{}).Listen(runtimeContext, "tcp", address)
			if err != nil {
				manager.close()
				return nil, fmt.Errorf("prepare TCP Forward %q: %w", configuration.Name, err)
			}
			runtime.listener = listener
		} else if configuration.Type == protocol.ForwardTypeUDP {
			address := net.JoinHostPort(configuration.ListenIP, fmt.Sprint(configuration.ListenPort))
			packet, err := (&net.ListenConfig{}).ListenPacket(runtimeContext, "udp", address)
			if err != nil {
				manager.close()
				return nil, fmt.Errorf("prepare UDP Forward %q: %w", configuration.Name, err)
			}
			runtime.packet = packet
			runtime.associations = make(map[string]*udpForwardAssociation)
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
	}
	return nil
}

func (manager *forwardManager) start() {
	manager.mutex.Lock()
	runtimes := make([]*forwardRuntime, 0, len(manager.runtimes))
	for _, runtime := range manager.runtimes {
		runtimes = append(runtimes, runtime)
	}
	manager.mutex.Unlock()
	for _, runtime := range runtimes {
		if runtime.listener == nil {
			if runtime.packet != nil {
				manager.waitGroup.Go(func() { manager.serveUDP(runtime) })
			}
		} else {
			manager.waitGroup.Go(func() { manager.acceptTCP(runtime) })
		}
	}
}

func (manager *forwardManager) serveUDP(runtime *forwardRuntime) {
	buffer := make([]byte, 8193)
	for {
		length, address, err := runtime.packet.ReadFrom(buffer)
		if err != nil {
			if manager.context.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			manager.logger.Error("UDP Forward listener failed", err)
			return
		}
		if length > 8192 {
			continue
		}
		key := address.String()
		manager.mutex.Lock()
		association := runtime.associations[key]
		if association == nil {
			association = &udpForwardAssociation{address: address, queue: make(chan []byte, 64)}
			runtime.associations[key] = association
			manager.waitGroup.Go(func() { manager.runUDPAssociation(runtime, key, association) })
		}
		manager.mutex.Unlock()
		payload := append([]byte(nil), buffer[:length]...)
		select {
		case association.queue <- payload:
		default:
		}
	}
}

func (manager *forwardManager) runUDPAssociation(
	runtime *forwardRuntime,
	key string,
	association *udpForwardAssociation,
) {
	defer func() {
		manager.mutex.Lock()
		if runtime.associations[key] == association {
			delete(runtime.associations, key)
		}
		manager.mutex.Unlock()
	}()
	offer, err := manager.requestForwardOffer(runtime)
	if err != nil {
		return
	}
	linkContext, cancelLink := context.WithCancel(manager.context)
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
	result := make(chan error, 2)
	go func() {
		buffer := make([]byte, 8192)
		for {
			payload, err := proxyudp.ReadDatagramInto(stream, buffer, 8192)
			if err == nil {
				_, err = runtime.packet.WriteTo(payload, association.address)
			}
			if err != nil {
				result <- err
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case payload := <-association.queue:
				if err := stream.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
					result <- err
					return
				}
				if err := proxyudp.WriteDatagram(stream, payload, 8192); err != nil {
					result <- err
					return
				}
			case <-linkContext.Done():
				result <- linkContext.Err()
				return
			}
		}
	}()
	_ = <-result
	_ = stream.Close()
}

func (manager *forwardManager) acceptTCP(runtime *forwardRuntime) {
	for {
		visitor, err := runtime.listener.Accept()
		if err != nil {
			if manager.context.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			manager.logger.Error("TCP Forward listener failed", err)
			return
		}
		manager.waitGroup.Go(func() { manager.serveTCP(runtime, visitor) })
	}
}

func (manager *forwardManager) serveTCP(runtime *forwardRuntime, visitor net.Conn) {
	defer visitor.Close()
	offer, err := manager.requestForwardOffer(runtime)
	if err != nil {
		return
	}
	manager.serveForwardStream(runtime, offer, func(linkContext context.Context, stream transport.Stream) {
		_, _ = proxytcp.Forward(linkContext, visitor, stream)
	})
}

func (manager *forwardManager) requestForwardOffer(
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
	case <-manager.context.Done():
		return protocol.ForwardLinkOffer{}, manager.context.Err()
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
	linkContext, cancelLink := context.WithCancel(manager.context)
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
	if runtime != nil && runtime.bindingID == revocation.BindingID {
		delete(manager.runtimes, revocation.Name)
	}
	manager.mutex.Unlock()
	if runtime != nil && runtime.bindingID == revocation.BindingID {
		runtime.cancel()
		if runtime.listener != nil {
			runtime.listener.Close()
		}
		if runtime.packet != nil {
			runtime.packet.Close()
		}
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
	for _, runtime := range manager.runtimes {
		runtime.cancel()
		if runtime.listener != nil {
			runtime.listener.Close()
		}
		if runtime.packet != nil {
			runtime.packet.Close()
		}
	}
	for _, cancel := range manager.links {
		cancel()
	}
	manager.mutex.Unlock()
	manager.waitGroup.Wait()
}
