package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestConfigurationAndForwardErrorsUseOwnedFields(t *testing.T) {
	configurationPayload, err := json.Marshal(ConfigurationError{
		Code:         ConfigurationErrorForwardTypeNotAllowed,
		ResourceKind: ConfigurationResourceForward,
		ResourceName: "database",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(configurationPayload, []byte(`"resource_name":"database"`)) ||
		bytes.Contains(configurationPayload, []byte("proxy_name")) {
		t.Fatalf("configuration error payload = %s", configurationPayload)
	}

	forwardPayload, err := json.Marshal(ForwardError{
		Code: ForwardErrorBindingInvalid, ForwardName: "database",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(forwardPayload, []byte(`"forward_name":"database"`)) ||
		bytes.Contains(forwardPayload, []byte("proxy_name")) {
		t.Fatalf("Forward error payload = %s", forwardPayload)
	}
}
