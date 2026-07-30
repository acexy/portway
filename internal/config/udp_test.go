package config

import "testing"

func TestDefaultUDPConfigIsValid(t *testing.T) {
	if err := validateUDPConfig(DefaultUDPConfig()); err != nil {
		t.Fatalf("default UDP configuration is invalid: %v", err)
	}
}

func TestUDPConfigRejectsUnsafeLimits(t *testing.T) {
	configuration := DefaultUDPConfig()
	configuration.MaxAssociationsPerClient = configuration.MaxAssociations + 1
	if err := validateUDPConfig(configuration); err == nil {
		t.Fatal("expected invalid UDP association limits")
	}
}

func TestClientUDPProxyConfigurationIsAccepted(t *testing.T) {
	configuration := DefaultClient()
	configuration.Authentication.Token = "test-token-with-at-least-32-random-bytes"
	configuration.Proxies = []ProxyConfig{{
		Name: "dns",
		Type: "udp",
		LocalIP: "127.0.0.1",
		LocalPort: 53,
		RemotePort: 5353,
	}}
	if err := validateClient(configuration); err != nil {
		t.Fatalf("valid UDP proxy configuration was rejected: %v", err)
	}
}
