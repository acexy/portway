package quic

import (
	"bytes"
	"testing"
)

func TestAuthenticationProofBindsDirectionAndConnectionContext(t *testing.T) {
	token := "test-only-authentication-binding-input"
	selector := bytes.Repeat([]byte{1}, authenticationSelectorSize)
	clientNonce := bytes.Repeat([]byte{2}, authenticationNonceSize)
	serverNonce := bytes.Repeat([]byte{3}, authenticationNonceSize)
	transcript := authenticationTranscript(selector, clientNonce, serverNonce)
	proof := authenticationProof(token, "server", transcript)
	if bytes.Equal(proof, authenticationProof(token, "client", transcript)) {
		t.Fatal("proof permits direction reflection")
	}
	for _, test := range []struct {
		name                               string
		selector, clientNonce, serverNonce []byte
	}{
		{"selector", bytes.Repeat([]byte{4}, authenticationSelectorSize), clientNonce, serverNonce},
		{"client_nonce", selector, bytes.Repeat([]byte{4}, authenticationNonceSize), serverNonce},
		{"server_nonce", selector, clientNonce, bytes.Repeat([]byte{4}, authenticationNonceSize)},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := authenticationTranscript(test.selector, test.clientNonce, test.serverNonce)
			if bytes.Equal(proof, authenticationProof(token, "server", changed)) {
				t.Fatal("proof does not authenticate changed context")
			}
		})
	}
}
