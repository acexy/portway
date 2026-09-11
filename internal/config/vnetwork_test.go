package config

import (
	"strings"
	"testing"
)

func TestValidateVirtualNetworkConfig(t *testing.T) {
	configuration := VirtualNetworkConfig{
		Enabled:        true,
		CIDR:           "172.20.0.0/16",
		ServerIP:       "172.20.0.1",
		PacketChannels: defaultVNetPacketChannels,
		ServerPorts: VNetPortPermissions{TCP: ForwardPortPermission{
			PortRanges: []PortRange{{Start: 22, End: 22}},
		}},
		Nodes: []VNetNodeConfig{{
			ClientID: "client-a",
			IP:       "172.20.0.2",
			Ports: VNetPortPermissions{UDP: ForwardPortPermission{
				PortRanges: []PortRange{{Start: 9000, End: 9100}},
			}},
		}},
	}
	if err := validateVirtualNetworkConfig(configuration); err != nil {
		t.Fatalf("validate VNet configuration: %v", err)
	}
}

func TestValidateVirtualNetworkConfigRejectsUnsafeValues(t *testing.T) {
	base := VirtualNetworkConfig{
		Enabled:        true,
		CIDR:           "172.20.0.0/16",
		ServerIP:       "172.20.0.1",
		PacketChannels: defaultVNetPacketChannels,
		ServerPorts: VNetPortPermissions{TCP: ForwardPortPermission{
			PortRanges: []PortRange{{Start: 22, End: 22}},
		}},
	}
	tests := []struct {
		name    string
		mutate  func(*VirtualNetworkConfig)
		message string
	}{
		{"public CIDR", func(value *VirtualNetworkConfig) { value.CIDR = "8.8.8.0/24" }, "private IPv4 CIDR"},
		{"network server IP", func(value *VirtualNetworkConfig) { value.ServerIP = "172.20.0.0" }, "usable host"},
		{"channel limit", func(value *VirtualNetworkConfig) { value.PacketChannels = 9 }, "packet_channels"},
		{"duplicate node IP", func(value *VirtualNetworkConfig) {
			value.Nodes = []VNetNodeConfig{{ClientID: "client-a", IP: "172.20.0.2"}, {ClientID: "client-b", IP: "172.20.0.2"}}
		}, "duplicates"},
		{"no ports", func(value *VirtualNetworkConfig) { value.ServerPorts = VNetPortPermissions{} }, "at least one"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := base
			test.mutate(&configuration)
			err := validateVirtualNetworkConfig(configuration)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("expected %q rejection, got %v", test.message, err)
			}
		})
	}
}

func TestValidateVirtualNetworkManagedClients(t *testing.T) {
	configuration := DefaultServer()
	configuration.VirtualNetwork.Nodes = []VNetNodeConfig{{ClientID: "client-a", IP: "172.20.0.2"}}
	configuration.ManagedClients = map[string]ManagedClientConfig{"client-a": {}}
	if err := validateVirtualNetworkManagedClients(configuration); err != nil {
		t.Fatalf("validate managed VNet client: %v", err)
	}
	configuration.VirtualNetwork.Nodes[0].ClientID = "governed-a"
	if err := validateVirtualNetworkManagedClients(configuration); err == nil {
		t.Fatal("expected non-managed VNet client rejection")
	}
}
