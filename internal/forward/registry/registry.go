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
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	forwardtcp "github.com/acexy/portway/internal/forward/tcp"
	forwardudp "github.com/acexy/portway/internal/forward/udp"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
)

const forwardTargetDialTimeout = 5 * time.Second

// Policy evaluates whether a declaration remains configured and currently active.
type Policy func(authentication.Context, protocol.ForwardDeclaration) (configured bool, active bool)

type binding struct {
	clientID       string
	sessionID      string
	bindingID      string
	declaration    protocol.ForwardDeclaration
	writer         *control.Writer
	authentication authentication.Context
	maxActiveLinks int
	active         bool
}

// Registry owns active Forward Bindings.
type Registry struct {
	mutex     sync.RWMutex
	bindings  map[string]*binding
	broker    *link.Broker
	policy    Policy
	udpConfig func() config.UDPConfig
	closed    bool
}

// Stats is a low-cardinality snapshot of Forward Binding state.
type Stats struct {
	Bindings       int
	ActiveBindings int
	TCPBindings    int
	UDPBindings    int
}

// SnapshotStats returns aggregate Forward Binding counts.
func (registry *Registry) SnapshotStats() Stats {
	registry.mutex.RLock()
	defer registry.mutex.RUnlock()
	stats := Stats{Bindings: len(registry.bindings)}
	for _, current := range registry.bindings {
		if current.active {
			stats.ActiveBindings++
		}
		if current.declaration.Type == protocol.ForwardTypeTCP {
			stats.TCPBindings++
		} else if current.declaration.Type == protocol.ForwardTypeUDP {
			stats.UDPBindings++
		}
	}
	return stats
}

// New creates a Forward Registry.
func New(broker *link.Broker, policy Policy, udpConfig func() config.UDPConfig) *Registry {
	return &Registry{
		bindings:  make(map[string]*binding),
		broker:    broker,
		policy:    policy,
		udpConfig: udpConfig,
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
) ([]protocol.ForwardResult, *protocol.ForwardError) {
	transaction, synchronizationError := registry.BeginSync(
		clientID,
		sessionID,
		writer,
		authenticationContext,
		maxActiveLinks,
		declarations,
	)
	if synchronizationError != nil {
		return nil, synchronizationError
	}
	results := append([]protocol.ForwardResult(nil), transaction.Results()...)
	if !transaction.Commit() {
		return nil, forwardError(
			protocol.ForwardErrorSessionInactive,
			"",
			"Forward generation changed while synchronizing",
		)
	}
	return results, nil
}

// Validate checks one complete declaration without mutating Registry state.
func (registry *Registry) Validate(
	authenticationContext authentication.Context,
	declarations []protocol.ForwardDeclaration,
) *protocol.ForwardError {
	names := make(map[string]struct{}, len(declarations))
	for _, declaration := range declarations {
		if declaration.Name == "" || declaration.TargetPort == 0 {
			return forwardError(protocol.ForwardErrorInvalidForward, declaration.Name, "invalid Forward declaration")
		}
		switch declaration.Type {
		case protocol.ForwardTypeTCP, protocol.ForwardTypeUDP:
		default:
			return forwardError(protocol.ForwardErrorInvalidForward, declaration.Name, "invalid Forward type")
		}
		if _, duplicate := names[declaration.Name]; duplicate {
			return forwardError(protocol.ForwardErrorInvalidForward, declaration.Name, "duplicate Forward name")
		}
		names[declaration.Name] = struct{}{}
		configured, _ := registry.policy(authenticationContext, declaration)
		if !configured {
			return forwardError(protocol.ForwardErrorTargetNotAllowed, declaration.Name, "Forward target is not allowed")
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
	if current == nil || !current.active || current.bindingID != request.BindingID ||
		current.declaration.Type != request.Type {
		registry.mutex.RUnlock()
		return rejectedOffer(request, protocol.ForwardErrorBindingInvalid, "Forward Binding is invalid")
	}
	bindingSnapshot := *current
	registry.mutex.RUnlock()
	_, active := registry.policy(bindingSnapshot.authentication, bindingSnapshot.declaration)
	if !active {
		return rejectedOffer(request, protocol.ForwardErrorTargetNotAllowed, "Forward target is not allowed")
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
		code := protocol.ForwardErrorInvalidRequest
		if errors.Is(err, link.ErrCapacityReached) {
			code = protocol.ForwardErrorLimitExceeded
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
	authorize := func() bool {
		_, active := registry.policy(current.authentication, current.declaration)
		return active
	}
	address := net.JoinHostPort(
		current.declaration.TargetIP,
		fmt.Sprint(current.declaration.TargetPort),
	)
	switch current.declaration.Type {
	case protocol.ForwardTypeTCP:
		return forwardtcp.TargetHandlerFactory(address, forwardTargetDialTimeout, authorize)
	case protocol.ForwardTypeUDP:
		configuration := registry.udpConfig()
		return forwardudp.TargetHandlerFactory(
			address, configuration.MaxDatagramSize, configuration.LinkWriteTimeout, authorize,
		)
	default:
		return func(context.Context) (link.StreamHandler, error) {
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
	deactivated := make([]*binding, 0)
	activated := make([]*binding, 0)
	refreshed := make([]*binding, 0)
	for _, current := range registry.bindings {
		_, active := registry.policy(current.authentication, current.declaration)
		bindingAffected := affectedPolicy(current.authentication, current.declaration)
		wasActive := current.active
		if current.active && !active {
			current.active = false
			deactivated = append(deactivated, current)
		}
		if !current.active && active {
			current.active = true
			activated = append(activated, current)
		}
		if bindingAffected || !active {
			affected = append(affected, current)
		}
		if bindingAffected && wasActive && active {
			refreshed = append(refreshed, current)
		}
	}
	registry.mutex.Unlock()
	for _, current := range affected {
		registry.broker.CancelBinding(current.bindingID)
	}
	for _, current := range deactivated {
		_ = current.writer.Write(protocol.MessageForwardBindingRevoked, protocol.ForwardBindingRevoked{
			Name:       current.declaration.Name,
			Type:       current.declaration.Type,
			BindingID:  current.bindingID,
			Generation: generation,
			Reason:     "policy_changed",
		})
	}
	for _, current := range refreshed {
		_ = current.writer.Write(protocol.MessageForwardBindingRevoked, protocol.ForwardBindingRevoked{
			Name: current.declaration.Name, Type: current.declaration.Type,
			BindingID: current.bindingID, Generation: generation, Reason: "policy_changed",
		})
	}
	activated = append(activated, refreshed...)
	for _, current := range activated {
		activation := protocol.ForwardBindingActivated{
			Name: current.declaration.Name, Type: current.declaration.Type,
			BindingID: current.bindingID, Generation: generation,
		}
		if current.declaration.Type == protocol.ForwardTypeUDP {
			activation.UDP = protocolUDPConfig(registry.udpConfig())
		}
		_ = current.writer.Write(protocol.MessageForwardBindingActivated, activation)
	}
}

func protocolUDPConfig(configuration config.UDPConfig) *protocol.ForwardUDPConfig {
	return &protocol.ForwardUDPConfig{
		AssociationIdleTimeout:                configuration.AssociationIdleTimeout,
		LinkWriteTimeout:                      configuration.LinkWriteTimeout,
		MaxDatagramSize:                       configuration.MaxDatagramSize,
		MaxAssociations:                       configuration.MaxAssociations,
		MaxAssociationsPerClient:              configuration.MaxAssociationsPerClient,
		MaxAssociationsPerForward:             configuration.MaxAssociationsPerProxy,
		MaxAssociationsPerSourceIP:            configuration.MaxAssociationsPerSourceIP,
		MaxPendingAssociations:                configuration.MaxPendingAssociations,
		MaxPendingAssociationsPerClient:       configuration.MaxPendingAssociationsPerClient,
		MaxPendingAssociationsPerForward:      configuration.MaxPendingAssociationsPerProxy,
		MaxNewAssociationsPerSecond:           configuration.MaxNewAssociationsPerSecond,
		MaxNewAssociationsPerSecondPerClient:  configuration.MaxNewAssociationsPerSecondPerClient,
		MaxNewAssociationsPerSecondPerForward: configuration.MaxNewAssociationsPerSecondPerProxy,
		MaxQueuedDatagramsPerAssociation:      configuration.MaxQueuedDatagramsPerAssociation,
		MaxQueuedBytesPerAssociation:          configuration.MaxQueuedBytesPerAssociation,
		MaxQueuedBytes:                        configuration.MaxQueuedBytes,
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

func forwardError(code protocol.ForwardErrorCode, name string, message string) *protocol.ForwardError {
	return &protocol.ForwardError{Code: code, ForwardName: name, Message: message, Retryable: false}
}

func rejectedOffer(
	request protocol.RequestForwardLink,
	code protocol.ForwardErrorCode,
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
