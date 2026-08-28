// Package registry owns server-side Forward declarations and Link creation.
package registry

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
)

const forwardTargetDialTimeout = 5 * time.Second

// Authorizer validates a concrete target against the current configuration.
type Authorizer func(authentication.Context, protocol.ForwardDeclaration) bool

type binding struct {
	clientID       string
	sessionID      string
	bindingID      string
	declaration    protocol.ForwardDeclaration
	writer         *control.Writer
	authentication authentication.Context
	maxActiveLinks int
}

// Registry owns active Forward Bindings.
type Registry struct {
	mutex      sync.RWMutex
	bindings   map[string]*binding
	broker     *link.Broker
	authorizer Authorizer
	closed     bool
}

// New creates a Forward Registry.
func New(broker *link.Broker, authorizer Authorizer) *Registry {
	return &Registry{
		bindings:   make(map[string]*binding),
		broker:     broker,
		authorizer: authorizer,
	}
}

// Sync atomically replaces one Session's complete Forward set.
func (registry *Registry) Sync(
	clientID string,
	sessionID string,
	writer *control.Writer,
	authenticationContext authentication.Context,
	maxActiveLinks int,
	declarations []protocol.ForwardDeclaration,
) ([]protocol.ForwardResult, *protocol.ProxyError) {
	if validationError := registry.Validate(authenticationContext, declarations); validationError != nil {
		return nil, validationError
	}

	registry.mutex.Lock()
	if registry.closed {
		registry.mutex.Unlock()
		return nil, forwardError(protocol.ProxyErrorSessionInactive, "", "Forward Registry is closed")
	}
	old := make([]*binding, 0)
	for key, existing := range registry.bindings {
		if existing.clientID == clientID && existing.sessionID == sessionID {
			old = append(old, existing)
			delete(registry.bindings, key)
		}
	}
	results := make([]protocol.ForwardResult, 0, len(declarations))
	for _, declaration := range declarations {
		bindingID, err := newBindingID()
		if err != nil {
			for _, previous := range old {
				registry.bindings[bindingKey(previous.clientID, previous.sessionID, previous.declaration.Name)] = previous
			}
			registry.mutex.Unlock()
			return nil, forwardError(protocol.ProxyErrorInvalidRequest, declaration.Name, "generate Forward Binding")
		}
		current := &binding{
			clientID: clientID, sessionID: sessionID, bindingID: bindingID,
			declaration: declaration, writer: writer,
			authentication: authenticationContext, maxActiveLinks: maxActiveLinks,
		}
		registry.bindings[bindingKey(clientID, sessionID, declaration.Name)] = current
		results = append(results, protocol.ForwardResult{
			Name: declaration.Name, Type: declaration.Type, BindingID: bindingID,
		})
	}
	registry.mutex.Unlock()
	for _, previous := range old {
		registry.broker.CancelBinding(previous.bindingID)
	}
	return results, nil
}

// Validate checks one complete declaration without mutating Registry state.
func (registry *Registry) Validate(
	authenticationContext authentication.Context,
	declarations []protocol.ForwardDeclaration,
) *protocol.ProxyError {
	names := make(map[string]struct{}, len(declarations))
	for _, declaration := range declarations {
		if declaration.Name == "" || declaration.TargetPort == 0 {
			return forwardError(protocol.ProxyErrorInvalidProxy, declaration.Name, "invalid Forward declaration")
		}
		switch declaration.Type {
		case protocol.ForwardTypeTCP, protocol.ForwardTypeUDP:
		default:
			return forwardError(protocol.ProxyErrorInvalidProxy, declaration.Name, "invalid Forward type")
		}
		if _, duplicate := names[declaration.Name]; duplicate {
			return forwardError(protocol.ProxyErrorInvalidProxy, declaration.Name, "duplicate Forward name")
		}
		names[declaration.Name] = struct{}{}
		if !registry.authorizer(authenticationContext, declaration) {
			return forwardError(protocol.ProxyErrorForwardTargetNotAllowed, declaration.Name, "Forward target is not allowed")
		}
	}
	return nil
}

// Offer prepares one client-originated Forward Link.
func (registry *Registry) Offer(
	clientID string,
	sessionID string,
	request protocol.RequestForwardLink,
) protocol.ForwardLinkOffer {
	registry.mutex.RLock()
	current := registry.bindings[bindingKey(clientID, sessionID, request.Name)]
	if current == nil || current.bindingID != request.BindingID ||
		current.declaration.Type != request.Type {
		registry.mutex.RUnlock()
		return rejectedOffer(request, protocol.ProxyErrorForwardBindingInvalid, "Forward Binding is invalid")
	}
	bindingSnapshot := *current
	registry.mutex.RUnlock()
	if !registry.authorizer(bindingSnapshot.authentication, bindingSnapshot.declaration) {
		return rejectedOffer(request, protocol.ProxyErrorForwardTargetNotAllowed, "Forward target is not allowed")
	}
	offer, err := registry.broker.OfferStream(link.Target{
		ClientID: clientID, SessionID: sessionID,
		ProxyName:      request.Name,
		ProxyType:      protocol.ProxyType(request.Type),
		BindingID:      request.BindingID,
		Writer:         bindingSnapshot.writer,
		Authentication: bindingSnapshot.authentication,
		MaxActiveLinks: bindingSnapshot.maxActiveLinks,
		Direction:      protocol.LinkDirectionForward,
	}, registry.handlerFactory(bindingSnapshot))
	if err != nil {
		code := protocol.ProxyErrorInvalidRequest
		if errors.Is(err, link.ErrCapacityReached) {
			code = protocol.ProxyErrorForwardLimitExceeded
		}
		return rejectedOffer(request, code, "Forward Link cannot be created")
	}
	return protocol.ForwardLinkOffer{
		RequestID:       request.RequestID,
		LinkID:          offer.LinkID,
		Name:            request.Name,
		Type:            request.Type,
		BindingID:       request.BindingID,
		Ticket:          offer.Ticket,
		ExpiresAtUnixMS: offer.ExpiresAtUnixMS,
	}
}

func (registry *Registry) handlerFactory(current binding) link.StreamHandlerFactory {
	return func(ctx context.Context) (link.StreamHandler, error) {
		if !registry.authorizer(current.authentication, current.declaration) {
			return nil, errors.New("Forward target is no longer allowed")
		}
		address := net.JoinHostPort(
			current.declaration.TargetIP,
			fmt.Sprint(current.declaration.TargetPort),
		)
		switch current.declaration.Type {
		case protocol.ForwardTypeTCP:
			dialContext, cancel := context.WithTimeout(ctx, forwardTargetDialTimeout)
			defer cancel()
			target, err := (&net.Dialer{}).DialContext(dialContext, "tcp", address)
			if err != nil {
				return nil, err
			}
			return func(linkContext context.Context, _ string, stream net.Conn) error {
				defer target.Close()
				_, forwardError := proxytcp.Forward(linkContext, stream, target)
				return forwardError
			}, nil
		case protocol.ForwardTypeUDP:
			target, err := net.Dial("udp", address)
			if err != nil {
				return nil, err
			}
			return func(linkContext context.Context, _ string, stream net.Conn) error {
				return proxyudp.Forward(linkContext, stream, target, 8192, 3*time.Second)
			}, nil
		default:
			return nil, errors.New("unsupported Forward type")
		}
	}
}

// Remove closes all Bindings owned by one Session.
func (registry *Registry) Remove(clientID string, sessionID string) {
	registry.mutex.Lock()
	removed := make([]*binding, 0)
	for key, current := range registry.bindings {
		if current.clientID == clientID && current.sessionID == sessionID {
			removed = append(removed, current)
			delete(registry.bindings, key)
		}
	}
	registry.mutex.Unlock()
	for _, current := range removed {
		registry.broker.CancelBinding(current.bindingID)
	}
}

// ApplyPolicy closes affected Links and revokes Bindings that are no longer legal.
func (registry *Registry) ApplyPolicy(
	generation uint64,
	affectedPolicy func(authentication.Context, protocol.ForwardDeclaration) bool,
) {
	registry.mutex.Lock()
	affected := make([]*binding, 0)
	revoked := make([]*binding, 0)
	for key, current := range registry.bindings {
		allowed := registry.authorizer(current.authentication, current.declaration)
		if !allowed {
			delete(registry.bindings, key)
			revoked = append(revoked, current)
		}
		if affectedPolicy(current.authentication, current.declaration) || !allowed {
			affected = append(affected, current)
		}
	}
	registry.mutex.Unlock()
	for _, current := range affected {
		registry.broker.CancelBinding(current.bindingID)
	}
	for _, current := range revoked {
		_ = current.writer.Write(protocol.MessageForwardBindingRevoked, protocol.ForwardBindingRevoked{
			Name:       current.declaration.Name,
			Type:       current.declaration.Type,
			BindingID:  current.bindingID,
			Generation: generation,
			Reason:     "policy_changed",
		})
	}
}

// Close closes every Forward Binding.
func (registry *Registry) Close() {
	registry.mutex.Lock()
	registry.closed = true
	bindings := make([]*binding, 0, len(registry.bindings))
	for _, current := range registry.bindings {
		bindings = append(bindings, current)
	}
	registry.bindings = make(map[string]*binding)
	registry.mutex.Unlock()
	for _, current := range bindings {
		registry.broker.CancelBinding(current.bindingID)
	}
}

func bindingKey(clientID string, sessionID string, name string) string {
	return clientID + "\x00" + sessionID + "\x00" + name
}

func newBindingID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func forwardError(code protocol.ProxyErrorCode, name string, message string) *protocol.ProxyError {
	return &protocol.ProxyError{Code: code, ProxyName: name, Message: message, Retryable: false}
}

func rejectedOffer(
	request protocol.RequestForwardLink,
	code protocol.ProxyErrorCode,
	message string,
) protocol.ForwardLinkOffer {
	return protocol.ForwardLinkOffer{
		RequestID: request.RequestID,
		Name:      request.Name,
		Type:      request.Type,
		BindingID: request.BindingID,
		Error:     forwardError(code, request.Name, message),
	}
}
