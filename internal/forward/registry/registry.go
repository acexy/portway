// Package registry owns server-side Forward declarations and Link creation.
package registry

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	forwardtcp "github.com/acexy/portway/internal/forward/tcp"
	forwardudp "github.com/acexy/portway/internal/forward/udp"
	"github.com/acexy/portway/internal/limits"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
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

type sessionKey struct {
	clientID  string
	sessionID string
}

// A set's identity is its publication generation, including an empty set.
// Membership is immutable after publication; policy updates only change bindings.
type bindingSet struct {
	bindings map[string]*binding
}

// Registry owns active Forward Bindings.
type Registry struct {
	mutex         sync.RWMutex
	sessions      map[sessionKey]*bindingSet
	broker        *link.Broker
	policy        Policy
	sessionActive func(string, string) bool
	udpConfig     func() config.UDPConfig
	udpLimiter    *proxyudp.Limiter
	closed        bool
}

// Stats is a low-cardinality snapshot of Forward Binding state.
type Stats struct {
	Bindings       int
	ActiveBindings int
	TCPBindings    int
	UDPBindings    int
	UDP            proxyudp.Stats
}

// SnapshotStats returns separate snapshots of Forward bindings and UDP resources.
func (registry *Registry) SnapshotStats() Stats {
	registry.mutex.RLock()
	var stats Stats
	for _, session := range registry.sessions {
		stats.Bindings += len(session.bindings)
		for _, current := range session.bindings {
			if current.active {
				stats.ActiveBindings++
			}
			if current.declaration.Type == protocol.ForwardTypeTCP {
				stats.TCPBindings++
			} else if current.declaration.Type == protocol.ForwardTypeUDP {
				stats.UDPBindings++
			}
		}
	}
	registry.mutex.RUnlock()
	stats.UDP = registry.udpLimiter.SnapshotStats()
	return stats
}

// New creates a Forward Registry.
func New(broker *link.Broker, policy Policy, udpConfig func() config.UDPConfig, sessionActive func(string, string) bool) *Registry {
	return &Registry{
		sessions:      make(map[sessionKey]*bindingSet),
		broker:        broker,
		policy:        policy,
		sessionActive: sessionActive,
		udpConfig:     udpConfig,
		udpLimiter:    proxyudp.NewLimiter(udpConfig()),
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
	if len(declarations) > limits.HardMaxBindingsPerClient {
		return forwardError(protocol.ForwardErrorLimitExceeded, "", "client Forward limit exceeded")
	}
	names := make(map[string]struct{}, len(declarations))
	for _, declaration := range declarations {
		address, addressError := netip.ParseAddr(declaration.TargetIP)
		if config.ValidateResourceName(declaration.Name) != nil || declaration.TargetPort == 0 ||
			addressError != nil || address.String() != declaration.TargetIP {
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
	if !registry.sessionActive(clientID, sessionID) {
		return rejectedOffer(request, protocol.ForwardErrorSessionInactive, "Forward Session is inactive")
	}
	registry.mutex.RLock()
	current := registry.bindingLocked(clientID, sessionID, request.Name)
	if current == nil || !current.active || current.bindingID != request.BindingID ||
		current.declaration.Type != request.Type {
		registry.mutex.RUnlock()
		return rejectedOffer(request, protocol.ForwardErrorBindingInvalid, "Forward Binding is invalid")
	}
	bindingSnapshot := *current
	_, active := registry.policy(bindingSnapshot.authentication, bindingSnapshot.declaration)
	if !active {
		registry.mutex.RUnlock()
		return rejectedOffer(request, protocol.ForwardErrorTargetNotAllowed, "Forward target is not allowed")
	}
	var reservation link.Reservation
	if request.Type == protocol.ForwardTypeUDP {
		lease, allowed := registry.udpLimiter.AcquireWithoutSource(clientID, request.Name, time.Now())
		if !allowed {
			registry.mutex.RUnlock()
			return rejectedOffer(request, protocol.ForwardErrorLimitExceeded, "Forward UDP capacity or rate reached")
		}
		reservation = lease
	}
	offer, err := registry.broker.OfferStream(link.Target{
		ClientID: clientID, SessionID: sessionID,
		BindingName:    request.Name,
		TrafficType:    link.TrafficType(request.Type),
		BindingID:      request.BindingID,
		Writer:         bindingSnapshot.writer,
		Authentication: bindingSnapshot.authentication,
		MaxActiveLinks: bindingSnapshot.maxActiveLinks,
		Direction:      protocol.LinkDirectionForward,
		Reservation:    reservation,
	}, registry.handlerFactory(bindingSnapshot))
	registry.mutex.RUnlock()
	if err != nil {
		if reservation != nil {
			reservation.Close()
		}
		code := protocol.ForwardErrorInvalidRequest
		if errors.Is(err, link.ErrCapacityReached) {
			code = protocol.ForwardErrorLimitExceeded
		}
		return rejectedOffer(request, code, "Forward Link cannot be created")
	}
	// Suspension may have cancelled the old set before this Offer entered it.
	// Recheck outside the binding lock, then remove any newly reserved ticket.
	if !registry.sessionActive(clientID, sessionID) {
		registry.broker.CancelForwardLink(clientID, sessionID, offer.LinkID)
		return rejectedOffer(request, protocol.ForwardErrorSessionInactive, "Forward Session is inactive")
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
		if !registry.sessionActive(current.clientID, current.sessionID) {
			return false
		}
		registry.mutex.RLock()
		defer registry.mutex.RUnlock()
		registered := registry.bindingLocked(current.clientID, current.sessionID, current.declaration.Name)
		if registry.closed || registered == nil || !registered.active || registered.bindingID != current.bindingID {
			return false
		}
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
		return func(context.Context) (link.StreamHandler, func(), error) {
			return nil, nil, errors.New("unsupported Forward type")
		}
	}
}

// Remove closes all Bindings owned by one Session.
func (registry *Registry) Remove(clientID string, sessionID string) {
	registry.mutex.Lock()
	key := sessionKey{clientID: clientID, sessionID: sessionID}
	removed := registry.sessions[key]
	delete(registry.sessions, key)
	registry.mutex.Unlock()
	if removed != nil {
		for _, current := range removed.bindings {
			registry.broker.CancelBinding(current.bindingID)
		}
	}
}

// ApplyPolicy publishes local policy and cancels affected Links before returning
// a notification batch. Delivery never runs under the Registry lock.
func (registry *Registry) ApplyPolicy(
	generation uint64,
	affectedPolicy func(authentication.Context, protocol.ForwardDeclaration) bool,
) *PolicyNotifications {
	registry.mutex.Lock()
	configuration := registry.udpConfig()
	registry.udpLimiter.UpdateConfiguration(configuration)
	affected := make([]string, 0)
	notifications := &PolicyNotifications{sessions: make(map[*control.Writer][]policyNotice)}
	for _, session := range registry.sessions {
		for _, current := range session.bindings {
			_, active := registry.policy(current.authentication, current.declaration)
			changed := affectedPolicy(current.authentication, current.declaration)
			wasActive := current.active
			current.active = active
			if changed || !active {
				affected = append(affected, current.bindingID)
			}
			if wasActive && (!active || changed) {
				notifications.add(current.writer, protocol.MessageForwardBindingRevoked, protocol.ForwardBindingRevoked{
					Name: current.declaration.Name, Type: current.declaration.Type,
					BindingID: current.bindingID, Generation: generation, Reason: "policy_changed",
				})
			}
			if active && (!wasActive || changed) {
				activation := protocol.ForwardBindingActivated{
					Name: current.declaration.Name, Type: current.declaration.Type,
					BindingID: current.bindingID, Generation: generation,
				}
				if current.declaration.Type == protocol.ForwardTypeUDP {
					activation.UDP = config.ForwardUDPProtocolConfig(configuration)
				}
				notifications.add(current.writer, protocol.MessageForwardBindingActivated, activation)
			}
		}
	}
	registry.mutex.Unlock()
	for _, bindingID := range affected {
		registry.broker.CancelBinding(bindingID)
	}
	return notifications
}

// Close closes every Forward Binding.
func (registry *Registry) Close() {
	registry.mutex.Lock()
	registry.closed = true
	sessions := registry.sessions
	registry.sessions = nil
	registry.mutex.Unlock()
	for _, session := range sessions {
		for _, current := range session.bindings {
			registry.broker.CancelBinding(current.bindingID)
		}
	}
}

// bindingLocked requires the Registry read or write lock.
func (registry *Registry) bindingLocked(clientID, sessionID, name string) *binding {
	if session := registry.sessions[sessionKey{clientID: clientID, sessionID: sessionID}]; session != nil {
		return session.bindings[name]
	}
	return nil
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
