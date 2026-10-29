package token

import (
	"bytes"
	"testing"

	"github.com/acexy/portway/internal/protocol"
)

func TestDirectionalKeysBindRoleAndBothNonces(t *testing.T) {
	token := "test-only-key-separation-input"
	clientNonce, serverNonce := bytes.Repeat([]byte{1}, handshakeNonceSize), bytes.Repeat([]byte{2}, handshakeNonceSize)
	clientKey, serverKey, err := deriveDirectionalKeys(token, clientNonce, serverNonce, protocol.RoleControl)
	if err != nil {
		t.Fatal(err)
	}
	if len(clientKey) != 32 || len(serverKey) != 32 || bytes.Equal(clientKey, serverKey) {
		t.Fatal("directions do not have distinct AES-256 keys")
	}
	for _, change := range []struct {
		name                     string
		clientNonce, serverNonce []byte
		role                     protocol.Role
	}{
		{"client_nonce", bytes.Repeat([]byte{3}, handshakeNonceSize), serverNonce, protocol.RoleControl},
		{"server_nonce", clientNonce, bytes.Repeat([]byte{3}, handshakeNonceSize), protocol.RoleControl},
		{"role", clientNonce, serverNonce, protocol.RoleData},
	} {
		t.Run(change.name, func(t *testing.T) {
			changedClient, changedServer, err := deriveDirectionalKeys(token, change.clientNonce, change.serverNonce, change.role)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(clientKey, changedClient) || bytes.Equal(serverKey, changedServer) {
				t.Fatal("changed connection context reused a directional key")
			}
		})
	}
	transcript := []byte("test handshake transcript")
	if bytes.Equal(handshakeProof(token, "client", transcript), handshakeProof(token, "server", transcript)) {
		t.Fatal("handshake proof permits direction reflection")
	}
}
