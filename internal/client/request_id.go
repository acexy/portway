package client

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func newRequestID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
