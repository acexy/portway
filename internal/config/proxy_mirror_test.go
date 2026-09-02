package config

import (
	"testing"

	"github.com/acexy/portway/internal/protocol"
)

func TestValidateProxyMirrorConfigurationAllowsGovernedGroup(t *testing.T) {
	configuration := DefaultServer()
	configuration.GovernedClients = map[string]GovernedClientConfig{
		"client-a": governedMirrorClient("client-a", 22000),
		"client-b": governedMirrorClient("client-b", 22000),
	}
	configuration.Proxies.Mirror.Governed = []ProxyMirrorGroupConfig{{
		Name: "telemetry", Type: protocol.ProxyTypeTCP,
		Public:          mirrorPublic(22000),
		PrimaryClientID: "client-a", ClientIDs: []string{"client-a", "client-b"},
	}}
	if err := ValidateProxyMirrorConfiguration(configuration); err != nil {
		t.Fatal(err)
	}
}

func TestValidateProxyMirrorConfigurationRejectsPrimaryOutsideMembers(t *testing.T) {
	configuration := DefaultServer()
	configuration.GovernedClients = map[string]GovernedClientConfig{
		"client-a": governedMirrorClient("client-a", 22000),
	}
	configuration.Proxies.Mirror.Governed = []ProxyMirrorGroupConfig{{
		Name: "telemetry", Type: protocol.ProxyTypeTCP,
		Public:          mirrorPublic(22000),
		PrimaryClientID: "client-b", ClientIDs: []string{"client-a"},
	}}
	if err := ValidateProxyMirrorConfiguration(configuration); err == nil {
		t.Fatal("expected primary membership validation failure")
	}
}

func TestValidateProxyMirrorConfigurationAllowsManagedSharedPort(t *testing.T) {
	configuration := DefaultServer()
	configuration.ManagedClients = map[string]ManagedClientConfig{
		"managed-a": managedMirrorClient("managed-a", 32000),
		"managed-b": managedMirrorClient("managed-b", 32000),
	}
	configuration.Proxies.Mirror.Managed = []ProxyMirrorGroupConfig{{
		Name: "telemetry", Type: protocol.ProxyTypeUDP,
		Public:          mirrorPublic(32000),
		PrimaryClientID: "managed-a", ClientIDs: []string{"managed-a", "managed-b"},
	}}
	if err := ValidateProxyMirrorConfiguration(configuration); err != nil {
		t.Fatal(err)
	}
}

func TestValidateProxyMirrorConfigurationAllowsMultiplePorts(t *testing.T) {
	configuration := DefaultServer()
	configuration.GovernedClients = map[string]GovernedClientConfig{
		"client-a": governedMirrorClient("client-a", 22000),
	}
	configuration.GovernedClients["client-a"] = GovernedClientConfig{
		Authentication: ClientAuthenticationConfig{ClientID: "client-a"},
		Permissions: GovernedPermissions{Proxies: GovernedProxyPermissions{
			TCP: &ProxyPermission{RemotePortRanges: []PortRange{{Start: 22000, End: 22002}}},
		}},
	}
	configuration.Proxies.Mirror.Governed = []ProxyMirrorGroupConfig{{
		Name: "telemetry", Type: protocol.ProxyTypeTCP,
		Public:          ProxyMirrorPublicConfig{PortRanges: []PortRange{{Start: 22000, End: 22002}}},
		PrimaryClientID: "client-a", ClientIDs: []string{"client-a"},
	}}
	if err := ValidateProxyMirrorConfiguration(configuration); err != nil {
		t.Fatal(err)
	}
}

func mirrorPublic(port uint16) ProxyMirrorPublicConfig {
	return ProxyMirrorPublicConfig{PortRanges: []PortRange{{Start: port, End: port}}}
}

func governedMirrorClient(clientID string, port uint16) GovernedClientConfig {
	return GovernedClientConfig{
		Authentication: ClientAuthenticationConfig{ClientID: clientID},
		Permissions: GovernedPermissions{Proxies: GovernedProxyPermissions{
			TCP: &ProxyPermission{RemotePortRanges: []PortRange{{Start: port, End: port}}},
		}},
	}
}

func managedMirrorClient(clientID string, port uint16) ManagedClientConfig {
	return ManagedClientConfig{
		Authentication: ClientAuthenticationConfig{ClientID: clientID},
		Configuration: ManagedConfiguration{Revision: 1, Proxies: []ProxyConfig{{
			Name: "telemetry", Type: protocol.ProxyTypeUDP,
			Local:  EndpointConfig{IP: "127.0.0.1", Port: 53},
			Public: ProxyPublicConfig{Port: port},
		}}},
	}
}
