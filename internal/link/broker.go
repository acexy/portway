// Package link coordinates logical data links independently of proxy protocols.
package link

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
)

// ErrCapacityReached reports that the bounded Link broker cannot accept another Link.
var ErrCapacityReached = errors.New("link capacity reached")

// Target identifies the authenticated owner and proxy binding of one link.
type Target struct {
	ClientID        string
	SessionID       string
	ProxyName       string
	ProxyType       protocol.ProxyType
	BindingID       string
	Writer          *control.Writer
	MaxDatagramSize int
	WriteTimeout    time.Duration
	Authentication  authentication.Context
	MaxActiveLinks  int
	Direction       protocol.LinkDirection
}

// StreamHandler handles one authenticated active Link.
type StreamHandler func(context.Context, string, net.Conn) error

// StreamHandlerFactory prepares target-side resources before Bind is accepted.
type StreamHandlerFactory func(context.Context) (StreamHandler, error)

type brokerPendingLink struct {
	target         Target
	linkID         string
	ticketDigest   [sha256.Size]byte
	expiresAt      time.Time
	timer          *time.Timer
	onCancel       func(string)
	ready          chan linkOpenResult
	handler        func(context.Context, string, net.Conn) error
	handlerFactory StreamHandlerFactory
}

type brokerActiveLink struct {
	target     Target
	connection *managedLinkConnection
}

type linkOpenResult struct {
	connection net.Conn
	err        error
}

// Stats is a low-cardinality snapshot of logical link state.
type Stats struct {
	Pending int
	Active  int
}

// SnapshotStats returns aggregate link counts.
func (broker *Broker) SnapshotStats() Stats {
	broker.mutex.Lock()
	defer broker.mutex.Unlock()
	return Stats{Pending: len(broker.pending), Active: len(broker.active)}
}

// Broker owns pending and active logical data links.
type Broker struct {
	mutex          sync.Mutex
	pending        map[string]*brokerPendingLink
	active         map[string]*brokerActiveLink
	pendingClients map[string]int
	pendingProxies map[string]int
	activeClients  map[string]int
	activeProxies  map[string]int
	closed         bool
	closeOnce      sync.Once
}

// NewBroker creates a link broker.
func NewBroker(ctx context.Context) *Broker {
	broker := &Broker{
		pending:        make(map[string]*brokerPendingLink),
		active:         make(map[string]*brokerActiveLink),
		pendingClients: make(map[string]int),
		pendingProxies: make(map[string]int),
		activeClients:  make(map[string]int),
		activeProxies:  make(map[string]int),
	}
	context.AfterFunc(ctx, broker.Close)
	return broker
}

func (broker *Broker) ServeStream(
	target Target,
	onCancel func(string),
	handler func(context.Context, string, net.Conn) error,
) (string, error) {
	return broker.request(target, onCancel, nil, handler)
}

// OfferStream creates a client-originated pending Link without sending open_link.
func (broker *Broker) OfferStream(
	target Target,
	factory StreamHandlerFactory,
) (protocol.OpenLink, error) {
	return broker.createPending(target, nil, nil, nil, factory)
}

// ServeStreamContext requests one stream and cancels its pending or active
// state when the supplied context ends.
func (broker *Broker) ServeStreamContext(
	ctx context.Context,
	target Target,
	onCancel func(string),
	handler func(context.Context, string, net.Conn) error,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	linkID, err := broker.request(target, onCancel, nil, handler)
	if err != nil {
		return err
	}
	context.AfterFunc(ctx, func() {
		broker.cancelAny(linkID, ctx.Err())
	})
	return nil
}

func (broker *Broker) OpenStream(ctx context.Context, target Target) (net.Conn, error) {
	ready := make(chan linkOpenResult, 1)
	linkID, err := broker.request(target, nil, ready, nil)
	if err != nil {
		return nil, err
	}
	select {
	case result := <-ready:
		return result.connection, result.err
	case <-ctx.Done():
		broker.cancel(linkID, true, ctx.Err())
		return nil, ctx.Err()
	}
}

func (broker *Broker) request(
	target Target,
	onCancel func(string),
	ready chan linkOpenResult,
	handler func(context.Context, string, net.Conn) error,
) (string, error) {
	offer, err := broker.createPending(target, onCancel, ready, handler, nil)
	if err != nil {
		return "", err
	}
	if err := target.Writer.Write(protocol.MessageOpenLink, offer); err != nil {
		broker.cancel(offer.LinkID, false, err)
		return offer.LinkID, err
	}
	return offer.LinkID, nil
}

func (broker *Broker) createPending(
	target Target,
	onCancel func(string),
	ready chan linkOpenResult,
	handler StreamHandler,
	handlerFactory StreamHandlerFactory,
) (protocol.OpenLink, error) {
	broker.mutex.Lock()
	if broker.closed || broker.limitReachedLocked(target) {
		broker.mutex.Unlock()
		return protocol.OpenLink{}, ErrCapacityReached
	}
	broker.mutex.Unlock()

	linkID, ticket, digest, err := newBrokerLinkCredentials()
	if err != nil {
		return protocol.OpenLink{}, err
	}
	broker.mutex.Lock()
	if broker.closed || broker.limitReachedLocked(target) {
		broker.mutex.Unlock()
		return protocol.OpenLink{}, ErrCapacityReached
	}
	expiresAt := time.Now().Add(pendingTimeout)
	pending := &brokerPendingLink{
		target:         target,
		linkID:         linkID,
		ticketDigest:   digest,
		expiresAt:      expiresAt,
		onCancel:       onCancel,
		ready:          ready,
		handler:        handler,
		handlerFactory: handlerFactory,
	}
	broker.pending[linkID] = pending
	broker.incrementPendingLocked(target)
	pending.timer = time.AfterFunc(pendingTimeout, func() {
		broker.cancel(linkID, true, context.DeadlineExceeded)
	})
	broker.mutex.Unlock()

	return protocol.OpenLink{
		LinkID:          linkID,
		ProxyName:       target.ProxyName,
		ProxyType:       target.ProxyType,
		BindingID:       target.BindingID,
		Ticket:          ticket,
		ExpiresAtUnixMS: expiresAt.UnixMilli(),
		MaxDatagramSize: uint32(target.MaxDatagramSize),
		WriteTimeoutMS:  uint32(target.WriteTimeout.Milliseconds()),
	}, nil
}

func (broker *Broker) Bind(
	ctx context.Context,
	connection net.Conn,
	binding protocol.BindLink,
	authenticationContext authentication.Context,
) error {
	return broker.BindWithActivation(
		ctx,
		connection,
		binding,
		authenticationContext,
		nil,
	)
}

// BindWithActivation binds a data stream and reports when the stream has
// atomically consumed its Pending Link and entered the Active set.
func (broker *Broker) BindWithActivation(
	ctx context.Context,
	connection net.Conn,
	binding protocol.BindLink,
	authenticationContext authentication.Context,
	onActivated func(),
) error {
	ticket, err := base64.RawURLEncoding.DecodeString(binding.Ticket)
	if err != nil || len(ticket) != 32 {
		return broker.rejectBinding(connection, binding.LinkID, protocol.LinkErrorInvalidBinding)
	}
	digest := sha256.Sum256(ticket)

	broker.mutex.Lock()
	pending := broker.pending[binding.LinkID]
	if pending != nil && !time.Now().Before(pending.expiresAt) {
		delete(broker.pending, binding.LinkID)
		broker.decrementPendingLocked(pending.target)
		pending.timer.Stop()
		broker.mutex.Unlock()
		if pending.onCancel != nil {
			pending.onCancel(binding.LinkID)
		}
		if pending.ready != nil {
			pending.ready <- linkOpenResult{err: context.DeadlineExceeded}
		}
		return broker.rejectBinding(connection, binding.LinkID, protocol.LinkErrorInvalidBinding)
	}
	if pending == nil ||
		pending.target.ClientID != binding.ClientID ||
		pending.target.SessionID != binding.SessionID ||
		pending.target.ProxyType != binding.ProxyType ||
		pending.target.BindingID != binding.BindingID ||
		pending.target.Authentication != authenticationContext ||
		normalizeLinkDirection(pending.target.Direction) !=
			normalizeLinkDirection(binding.Direction) ||
		subtle.ConstantTimeCompare(digest[:], pending.ticketDigest[:]) != 1 {
		broker.mutex.Unlock()
		return broker.rejectBinding(connection, binding.LinkID, protocol.LinkErrorInvalidBinding)
	}
	delete(broker.pending, binding.LinkID)
	broker.decrementPendingLocked(pending.target)
	pending.timer.Stop()
	managed := newManagedLinkConnection(connection)
	broker.active[binding.LinkID] = &brokerActiveLink{
		target:     pending.target,
		connection: managed,
	}
	broker.incrementActiveLocked(pending.target)
	broker.mutex.Unlock()
	if pending.handlerFactory != nil {
		handler, prepareError := pending.handlerFactory(ctx)
		if prepareError != nil {
			rejectionError := broker.rejectBinding(
				connection,
				binding.LinkID,
				protocol.LinkErrorLocalDialFailed,
			)
			managed.Close()
			broker.finish(binding.LinkID)
			return fmt.Errorf("prepare data link target: %w: %v", rejectionError, prepareError)
		}
		pending.handler = handler
	}
	if onActivated != nil {
		onActivated()
	}

	if err := protocol.WriteControl(connection, protocol.MessageBindResult, protocol.BindResult{
		LinkID: binding.LinkID,
		Status: protocol.LinkStatusAccepted,
	}); err != nil {
		managed.Close()
		broker.finish(binding.LinkID)
		return err
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		managed.Close()
		broker.finish(binding.LinkID)
		return err
	}

	if pending.handler != nil {
		err = pending.handler(ctx, binding.LinkID, managed)
		managed.Close()
	} else {
		pending.ready <- linkOpenResult{connection: managed}
		select {
		case <-managed.done:
		case <-ctx.Done():
			managed.Close()
		}
	}
	broker.finish(binding.LinkID)
	return err
}

func normalizeLinkDirection(direction protocol.LinkDirection) protocol.LinkDirection {
	if direction == "" {
		return protocol.LinkDirectionProxy
	}
	return direction
}

func (broker *Broker) rejectBinding(
	connection net.Conn,
	linkID string,
	code protocol.LinkErrorCode,
) error {
	_ = protocol.WriteControl(connection, protocol.MessageBindResult, protocol.BindResult{
		LinkID: linkID,
		Status: protocol.LinkStatusRejected,
		Error:  &code,
	})
	return fmt.Errorf("bind data link: %s", code)
}

func (broker *Broker) cancel(linkID string, notify bool, err error) {
	broker.mutex.Lock()
	pending := broker.pending[linkID]
	if pending == nil {
		broker.mutex.Unlock()
		return
	}
	delete(broker.pending, linkID)
	broker.decrementPendingLocked(pending.target)
	broker.mutex.Unlock()
	pending.timer.Stop()
	if pending.onCancel != nil {
		pending.onCancel(linkID)
	}
	if pending.ready != nil {
		pending.ready <- linkOpenResult{err: err}
	}
	if notify {
		broker.notifyCancellation(pending.target, linkID)
	}
}

func (broker *Broker) cancelAny(linkID string, err error) {
	broker.mutex.Lock()
	active := broker.active[linkID]
	if active != nil {
		broker.mutex.Unlock()
		active.connection.Close()
		return
	}
	pending := broker.pending[linkID]
	if pending == nil {
		broker.mutex.Unlock()
		return
	}
	delete(broker.pending, linkID)
	broker.decrementPendingLocked(pending.target)
	broker.mutex.Unlock()
	pending.timer.Stop()
	if pending.onCancel != nil {
		pending.onCancel(linkID)
	}
	if pending.ready != nil {
		pending.ready <- linkOpenResult{err: err}
	}
	broker.notifyCancellation(pending.target, linkID)
}

func (broker *Broker) notifyCancellation(target Target, linkID string) {
	if target.Writer == nil {
		return
	}
	if normalizeLinkDirection(target.Direction) == protocol.LinkDirectionForward {
		_ = target.Writer.Write(
			protocol.MessageCancelForwardLink,
			protocol.CancelForwardLink{LinkID: linkID},
		)
		return
	}
	_ = target.Writer.Write(protocol.MessageCancelLink, protocol.CancelLink{
		LinkID: linkID,
		Reason: "link_cancelled",
	})
}

func (broker *Broker) CancelSession(clientID string, sessionID string) {
	broker.mutex.Lock()
	pendingIDs := make([]string, 0)
	active := make([]*managedLinkConnection, 0)
	for linkID, pending := range broker.pending {
		if pending.target.ClientID == clientID && pending.target.SessionID == sessionID {
			pendingIDs = append(pendingIDs, linkID)
		}
	}
	for _, link := range broker.active {
		if link.target.ClientID == clientID && link.target.SessionID == sessionID {
			active = append(active, link.connection)
		}
	}
	broker.mutex.Unlock()
	for _, linkID := range pendingIDs {
		broker.cancel(linkID, false, context.Canceled)
	}
	for _, connection := range active {
		connection.Close()
	}
}

func (broker *Broker) CancelBinding(bindingID string) {
	broker.mutex.Lock()
	pendingIDs := make([]string, 0)
	active := make([]*managedLinkConnection, 0)
	for linkID, pending := range broker.pending {
		if pending.target.BindingID == bindingID {
			pendingIDs = append(pendingIDs, linkID)
		}
	}
	for _, link := range broker.active {
		if link.target.BindingID == bindingID {
			active = append(active, link.connection)
		}
	}
	broker.mutex.Unlock()
	for _, linkID := range pendingIDs {
		broker.cancel(linkID, false, context.Canceled)
	}
	for _, connection := range active {
		connection.Close()
	}
}

// CancelLink cancels one pending or active Link by identifier.
func (broker *Broker) CancelLink(linkID string) {
	broker.cancelAny(linkID, context.Canceled)
}

func (broker *Broker) ReportFailure(
	clientID string,
	sessionID string,
	failure protocol.LinkFailed,
) {
	broker.mutex.Lock()
	pending := broker.pending[failure.LinkID]
	broker.mutex.Unlock()
	if pending != nil && pending.target.ClientID == clientID &&
		pending.target.SessionID == sessionID {
		broker.cancel(failure.LinkID, false, errors.New(string(failure.Code)))
	}
}

func (broker *Broker) Close() {
	broker.closeOnce.Do(func() {
		broker.mutex.Lock()
		broker.closed = true
		pendingIDs := make([]string, 0, len(broker.pending))
		active := make([]*managedLinkConnection, 0, len(broker.active))
		for linkID := range broker.pending {
			pendingIDs = append(pendingIDs, linkID)
		}
		for _, link := range broker.active {
			active = append(active, link.connection)
		}
		broker.mutex.Unlock()
		for _, linkID := range pendingIDs {
			broker.cancel(linkID, false, net.ErrClosed)
		}
		for _, connection := range active {
			connection.Close()
		}
	})
}

func (broker *Broker) finish(linkID string) {
	broker.mutex.Lock()
	active := broker.active[linkID]
	if active != nil {
		delete(broker.active, linkID)
		broker.decrementActiveLocked(active.target)
	}
	broker.mutex.Unlock()
}

func (broker *Broker) limitReachedLocked(target Target) bool {
	if len(broker.pending) >= maxPending ||
		len(broker.pending)+len(broker.active) >= maxActive {
		return true
	}
	proxyKey := brokerProxyKey(target)
	pendingClient := broker.pendingClients[target.ClientID]
	pendingProxy := broker.pendingProxies[proxyKey]
	activeClient := broker.activeClients[target.ClientID]
	activeProxy := broker.activeProxies[proxyKey]
	return pendingClient >= maxPendingPerClient ||
		pendingProxy >= maxPendingPerProxy ||
		(target.MaxActiveLinks > 0 &&
			pendingClient+activeClient >= target.MaxActiveLinks) ||
		pendingClient+activeClient >= maxActivePerClient ||
		pendingProxy+activeProxy >= maxActivePerProxy
}

func (broker *Broker) incrementPendingLocked(target Target) {
	broker.pendingClients[target.ClientID]++
	broker.pendingProxies[brokerProxyKey(target)]++
}

func (broker *Broker) decrementPendingLocked(target Target) {
	decrementBrokerCount(broker.pendingClients, target.ClientID)
	decrementBrokerCount(broker.pendingProxies, brokerProxyKey(target))
}

func (broker *Broker) incrementActiveLocked(target Target) {
	broker.activeClients[target.ClientID]++
	broker.activeProxies[brokerProxyKey(target)]++
}

func (broker *Broker) decrementActiveLocked(target Target) {
	decrementBrokerCount(broker.activeClients, target.ClientID)
	decrementBrokerCount(broker.activeProxies, brokerProxyKey(target))
}

func brokerProxyKey(target Target) string {
	return target.ClientID + "\x00" + target.ProxyName
}

func decrementBrokerCount(counts map[string]int, key string) {
	if counts[key] <= 1 {
		delete(counts, key)
		return
	}
	counts[key]--
}

func newBrokerLinkCredentials() (string, string, [sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	linkBytes := make([]byte, 16)
	if _, err := rand.Read(linkBytes); err != nil {
		return "", "", digest, err
	}
	ticketBytes := make([]byte, 32)
	if _, err := rand.Read(ticketBytes); err != nil {
		return "", "", digest, err
	}
	return base64.RawURLEncoding.EncodeToString(linkBytes),
		base64.RawURLEncoding.EncodeToString(ticketBytes),
		sha256.Sum256(ticketBytes),
		nil
}

type managedLinkConnection struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func newManagedLinkConnection(connection net.Conn) *managedLinkConnection {
	return &managedLinkConnection{Conn: connection, done: make(chan struct{})}
}

func (connection *managedLinkConnection) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(func() { close(connection.done) })
	return err
}

func (connection *managedLinkConnection) CloseWrite() error {
	closeWriter, ok := connection.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.New("link connection does not support half-close")
	}
	return closeWriter.CloseWrite()
}
