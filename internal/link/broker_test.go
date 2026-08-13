package link

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
)

func TestBrokerAppliesPerClientActiveLinkLimit(t *testing.T) {
	broker := NewBroker(context.Background())
	target := Target{ClientID: "client-a", MaxActiveLinks: 1}
	broker.active["active"] = &brokerActiveLink{target: target}
	broker.incrementActiveLocked(target)
	if !broker.limitReachedLocked(target) {
		t.Fatal("per-client active Link limit was not applied")
	}
	if broker.limitReachedLocked(Target{ClientID: "client-b", MaxActiveLinks: 1}) {
		t.Fatal("one client's active Link limit affected another client")
	}
}

func TestBrokerRejectsTicketFromDifferentAuthenticationGeneration(t *testing.T) {
	broker := NewBroker(context.Background())
	defer broker.Close()
	ticketBytes := []byte("ticket-with-at-least-32-random-bytes")
	ticket := base64.RawURLEncoding.EncodeToString(ticketBytes)
	current := authentication.Context{
		Mode:         authentication.ModeGoverned,
		ClientID:     "client-a",
		CredentialID: authentication.Selector("token-with-at-least-32-random-bytes"),
		Generation:   2,
	}
	broker.pending["link-a"] = &brokerPendingLink{
		target: Target{
			ClientID:       "client-a",
			SessionID:      "session-a",
			ProxyName:      "proxy-a",
			ProxyType:      protocol.ProxyTypeTCP,
			BindingID:      "binding-a",
			Authentication: current,
		},
		linkID:       "link-a",
		ticketDigest: sha256.Sum256(ticketBytes),
		expiresAt:    time.Now().Add(time.Hour),
		timer:        time.NewTimer(time.Hour),
	}
	serverConnection, clientConnection := net.Pipe()
	defer serverConnection.Close()
	defer clientConnection.Close()
	result := make(chan error, 1)
	go func() {
		stale := current
		stale.Generation--
		result <- broker.Bind(context.Background(), serverConnection, protocol.BindLink{
			ClientID:  "client-a",
			SessionID: "session-a",
			ProxyType: protocol.ProxyTypeTCP,
			BindingID: "binding-a",
			LinkID:    "link-a",
			Ticket:    ticket,
		}, stale)
	}()
	envelope, err := protocol.ReadControl(clientConnection)
	if err != nil {
		t.Fatal(err)
	}
	var bindingResult protocol.BindResult
	if err := protocol.DecodePayload(envelope, &bindingResult); err != nil {
		t.Fatal(err)
	}
	if bindingResult.Status != protocol.LinkStatusRejected {
		t.Fatalf("unexpected binding result: %+v", bindingResult)
	}
	if err := <-result; err == nil {
		t.Fatal("stale authentication generation was accepted")
	}
}

func TestBrokerRejectsExpiredTicketAndReleasesReservation(t *testing.T) {
	broker := NewBroker(context.Background())
	defer broker.Close()
	ticketBytes := make([]byte, 32)
	ticket := base64.RawURLEncoding.EncodeToString(ticketBytes)
	target := Target{ClientID: "client-a", ProxyName: "proxy-a"}
	broker.pending["link-a"] = &brokerPendingLink{
		target:       target,
		linkID:       "link-a",
		ticketDigest: sha256.Sum256(ticketBytes),
		expiresAt:    time.Now().Add(-time.Second),
		timer:        time.NewTimer(time.Hour),
	}
	broker.incrementPendingLocked(target)

	serverConnection, clientConnection := net.Pipe()
	defer serverConnection.Close()
	defer clientConnection.Close()
	result := make(chan error, 1)
	go func() {
		result <- broker.Bind(context.Background(), serverConnection, protocol.BindLink{
			ClientID: "client-a", LinkID: "link-a", Ticket: ticket,
		}, authentication.Context{})
	}()
	if _, err := protocol.ReadControl(clientConnection); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("expired ticket was accepted")
	}
	broker.mutex.Lock()
	defer broker.mutex.Unlock()
	if len(broker.pending) != 0 || len(broker.pendingClients) != 0 {
		t.Fatal("expired ticket retained its capacity reservation")
	}
}

func TestBrokerPendingLinksReserveActiveCapacity(t *testing.T) {
	broker := NewBroker(context.Background())
	target := Target{ClientID: "client-a", ProxyName: "proxy-a"}
	broker.activeClients[target.ClientID] = maxActivePerClient - 1
	broker.pendingClients[target.ClientID] = 1
	if !broker.limitReachedLocked(target) {
		t.Fatal("pending Link did not reserve per-client active capacity")
	}
	broker.activeClients[target.ClientID] = 0
	broker.pendingClients[target.ClientID] = 0
	broker.activeProxies[brokerProxyKey(target)] = maxActivePerProxy - 1
	broker.pendingProxies[brokerProxyKey(target)] = 1
	if !broker.limitReachedLocked(target) {
		t.Fatal("pending Link did not reserve per-proxy active capacity")
	}
}

func TestBrokerMaintainsCapacityCountersAcrossBindLifecycle(t *testing.T) {
	broker := NewBroker(context.Background())
	defer broker.Close()
	serverControl, clientControl := net.Pipe()
	defer serverControl.Close()
	defer clientControl.Close()
	target := Target{
		ClientID: "client-a", SessionID: "session-a", ProxyName: "proxy-a",
		ProxyType: protocol.ProxyTypeTCP, BindingID: "binding-a",
		Writer: control.NewWriter(serverControl),
	}
	handlerObserved := make(chan bool, 1)
	requestResult := make(chan error, 1)
	go func() {
		requestResult <- broker.ServeStream(target, nil, func(_ context.Context, _ net.Conn) error {
			broker.mutex.Lock()
			active := broker.activeClients[target.ClientID] == 1 &&
				broker.activeProxies[brokerProxyKey(target)] == 1 &&
				broker.pendingClients[target.ClientID] == 0
			broker.mutex.Unlock()
			handlerObserved <- active
			return nil
		})
	}()
	envelope, err := protocol.ReadControl(clientControl)
	if err != nil {
		t.Fatal(err)
	}
	var open protocol.OpenLink
	if err := protocol.DecodePayload(envelope, &open); err != nil {
		t.Fatal(err)
	}
	if err := <-requestResult; err != nil {
		t.Fatal(err)
	}
	broker.mutex.Lock()
	pendingCounted := broker.pendingClients[target.ClientID] == 1 &&
		broker.pendingProxies[brokerProxyKey(target)] == 1
	broker.mutex.Unlock()
	if !pendingCounted {
		t.Fatal("pending Link counters were not incremented")
	}

	serverData, clientData := net.Pipe()
	defer serverData.Close()
	defer clientData.Close()
	bindResult := make(chan error, 1)
	go func() {
		bindResult <- broker.Bind(context.Background(), serverData, protocol.BindLink{
			ClientID: target.ClientID, SessionID: target.SessionID,
			ProxyType: target.ProxyType, BindingID: target.BindingID,
			LinkID: open.LinkID, Ticket: open.Ticket,
		}, authentication.Context{})
	}()
	if _, err := protocol.ReadControl(clientData); err != nil {
		t.Fatal(err)
	}
	if !<-handlerObserved {
		t.Fatal("pending and active Link counters did not transition atomically")
	}
	if err := <-bindResult; err != nil {
		t.Fatal(err)
	}
	broker.mutex.Lock()
	defer broker.mutex.Unlock()
	if len(broker.pendingClients) != 0 || len(broker.pendingProxies) != 0 ||
		len(broker.activeClients) != 0 || len(broker.activeProxies) != 0 {
		t.Fatal("Link capacity counters were not released")
	}
}

func TestBrokerParentContextReleasesPendingLinks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	broker := NewBroker(ctx)
	serverControl, clientControl := net.Pipe()
	defer serverControl.Close()
	defer clientControl.Close()
	cancelled := make(chan struct{}, 1)
	requestResult := make(chan error, 1)
	go func() {
		requestResult <- broker.ServeStream(
			Target{
				ClientID: "client-a", SessionID: "session-a", ProxyName: "proxy-a",
				ProxyType: protocol.ProxyTypeTCP, BindingID: "binding-a",
				Writer: control.NewWriter(serverControl),
			},
			func() { cancelled <- struct{}{} },
			func(context.Context, net.Conn) error { return nil },
		)
	}()
	if _, err := protocol.ReadControl(clientControl); err != nil {
		t.Fatal(err)
	}
	if err := <-requestResult; err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("parent context did not cancel the pending Link")
	}
	broker.mutex.Lock()
	defer broker.mutex.Unlock()
	if len(broker.pending) != 0 || len(broker.pendingClients) != 0 ||
		len(broker.pendingProxies) != 0 {
		t.Fatal("parent context cancellation retained pending Link state")
	}
}
