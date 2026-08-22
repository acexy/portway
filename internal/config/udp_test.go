package config

import "testing"

func TestDefaultUDPConfigIsValid(t *testing.T) {
	configuration := DefaultUDPConfig()
	if configuration.MaxDatagramSize != 8*1024 {
		t.Fatalf("default UDP datagram size = %d, want %d", configuration.MaxDatagramSize, 8*1024)
	}
	if err := validateUDPConfig(configuration); err != nil {
		t.Fatalf("default UDP configuration is invalid: %v", err)
	}
}

func TestUDPConfigRejectsDatagramSizeAbovePlatformLimit(t *testing.T) {
	platformMaximum, err := platformUDPMaxDatagramSize()
	if err != nil {
		t.Fatal(err)
	}
	if platformMaximum >= udpHardMaxDatagramSize {
		t.Skip("platform limit is not lower than the protocol hard limit")
	}
	configuration := DefaultUDPConfig()
	configuration.MaxDatagramSize = platformMaximum + 1
	if err := validateUDPConfig(configuration); err == nil {
		t.Fatal("expected platform UDP datagram limit rejection")
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
	configuration.Authentication.Token = "cG9ydHdheS10ZXN0LWNsaWVudC10b2tlbi0wMDAwMDA"
	configuration.Proxies = []ProxyConfig{{
		Name:       "dns",
		Type:       "udp",
		LocalIP:    "127.0.0.1",
		LocalPort:  53,
		RemotePort: 5353,
	}}
	if err := validateClient(configuration); err != nil {
		t.Fatalf("valid UDP proxy configuration was rejected: %v", err)
	}
}
