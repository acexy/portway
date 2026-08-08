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
}

type brokerPendingLink struct {
	target       Target
	linkID       string
	ticketDigest [sha256.Size]byte
	timer        *time.Timer
	onCancel     func()
	ready        chan linkOpenResult
	handler      func(context.Context, net.Conn) error
}

type brokerActiveLink struct {
	target     Target
	connection *managedLinkConnection
}

type linkOpenResult struct {
	connection net.Conn
	err        error
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
	onCancel func(),
	handler func(context.Context, net.Conn) error,
) error {
	_, err := broker.request(target, onCancel, nil, handler)
	return err
}

// ServeStreamContext requests one stream and cancels its pending or active
// state when the supplied context ends.
func (broker *Broker) ServeStreamContext(
	ctx context.Context,
	target Target,
	onCancel func(),
	handler func(context.Context, net.Conn) error,
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
	onCancel func(),
	ready chan linkOpenResult,
	handler func(context.Context, net.Conn) error,
) (string, error) {
	linkID, ticket, digest, err := newBrokerLinkCredentials()
	if err != nil {
		return "", err
	}
	broker.mutex.Lock()
	if broker.closed || broker.limitReachedLocked(target) {
		broker.mutex.Unlock()
		return "", errors.New("link capacity reached")
	}
	pending := &brokerPendingLink{
		target:       target,
		linkID:       linkID,
		ticketDigest: digest,
		onCancel:     onCancel,
		ready:        ready,
		handler:      handler,
	}
	broker.pending[linkID] = pending
	broker.incrementPendingLocked(target)
	pending.timer = time.AfterFunc(pendingTimeout, func() {
		broker.cancel(linkID, true, context.DeadlineExceeded)
	})
	broker.mutex.Unlock()

	if err := target.Writer.Write(protocol.MessageOpenLink, protocol.OpenLink{
		LinkID:          linkID,
		ProxyName:       target.ProxyName,
		ProxyType:       target.ProxyType,
		BindingID:       target.BindingID,
		Ticket:          ticket,
		ExpiresAtUnixMS: time.Now().Add(pendingTimeout).UnixMilli(),
		MaxDatagramSize: uint32(target.MaxDatagramSize),
		WriteTimeoutMS:  uint32(target.WriteTimeout.Milliseconds()),
	}); err != nil {
		broker.cancel(linkID, false, err)
		return "", err
	}
	return linkID, nil
}

func (broker *Broker) Bind(
	ctx context.Context,
	connection net.Conn,
	binding protocol.BindLink,
	authenticationContext authentication.Context,
) error {
	ticket, err := base64.RawURLEncoding.DecodeString(binding.Ticket)
	if err != nil {
		return broker.rejectBinding(connection, binding.LinkID, protocol.LinkErrorInvalidBinding)
	}
	digest := sha256.Sum256(ticket)

	broker.mutex.Lock()
	pending := broker.pending[binding.LinkID]
	if pending == nil ||
		pending.target.ClientID != binding.ClientID ||
		pending.target.SessionID != binding.SessionID ||
		pending.target.ProxyType != binding.ProxyType ||
		pending.target.BindingID != binding.BindingID ||
		pending.target.Authentication != authenticationContext ||
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
		err = pending.handler(ctx, managed)
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
		pending.onCancel()
	}
	if pending.ready != nil {
		pending.ready <- linkOpenResult{err: err}
	}
	if notify {
		_ = pending.target.Writer.Write(protocol.MessageCancelLink, protocol.CancelLink{
			LinkID: linkID,
			Reason: "link_cancelled",
		})
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
		pending.onCancel()
	}
	if pending.ready != nil {
		pending.ready <- linkOpenResult{err: err}
	}
	_ = pending.target.Writer.Write(protocol.MessageCancelLink, protocol.CancelLink{
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
		len(broker.active) >= maxActive {
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
		activeClient >= maxActivePerClient ||
		activeProxy >= maxActivePerProxy
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
