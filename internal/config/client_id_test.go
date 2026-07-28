package config

import (
	"strings"
	"testing"
)

func TestEnsureClientIDKeepsConfiguredValue(t *testing.T) {
	configuration := ClientConfig{ClientID: "home-server"}

	clientID, generated, err := EnsureClientID(&configuration)
	if err != nil {
		t.Fatal(err)
	}
	if generated || clientID != "home-server" || configuration.ClientID != clientID {
		t.Fatalf(
			"unexpected configured client ID result: id=%q generated=%t",
			clientID,
			generated,
		)
	}
}

func TestEnsureClientIDGeneratesProcessScopedValue(t *testing.T) {
	configuration := ClientConfig{}

	firstClientID, generated, err := EnsureClientID(&configuration)
	if err != nil {
		t.Fatal(err)
	}
	if !generated || !strings.HasPrefix(firstClientID, "pw_c_") {
		t.Fatalf("unexpected generated client ID %q", firstClientID)
	}
	if err := ValidateClientID(firstClientID); err != nil {
		t.Fatalf("generated client ID is invalid: %v", err)
	}

	secondClientID, generated, err := EnsureClientID(&configuration)
	if err != nil {
		t.Fatal(err)
	}
	if generated || secondClientID != firstClientID {
		t.Fatalf(
			"client ID changed within one process: first=%q second=%q",
			firstClientID,
			secondClientID,
		)
	}
}
