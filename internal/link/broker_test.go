package link

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
)

func TestBrokerAppliesPerClientActiveLinkLimit(t *testing.T) {
	broker := NewBroker(context.Background())
	target := Target{ClientID: "client-a", MaxActiveLinks: 1}
	broker.active["active"] = &brokerActiveLink{target: target}
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
