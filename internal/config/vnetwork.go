package config

import (
	"errors"
	"fmt"
	"net/netip"
)

const (
	defaultVNetPacketChannels = 4
	hardMaxVNetPacketChannels = 8
	hardMaxVNetNodes          = 256
)

func validateVirtualNetworkConfig(configuration VirtualNetworkConfig) error {
	if configuration.NetworkMode != "" && configuration.NetworkMode != VNetNetworkModeTUN &&
		configuration.NetworkMode != VNetNetworkModeLoopback {
		return errors.New("virtual_network.network_mode must be tun or loopback")
	}
	prefix, err := netip.ParsePrefix(configuration.CIDR)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() ||
		prefix.String() != configuration.CIDR {
		return errors.New("virtual_network.cidr must be a canonical private IPv4 CIDR")
	}
	if !prefix.Addr().IsPrivate() {
		return errors.New("virtual_network.cidr must be a private IPv4 CIDR")
	}
	if prefix.Bits() > 30 {
		return errors.New("virtual_network.cidr must contain at least two usable addresses")
	}
	serverIP, err := parseVNetHost(prefix, configuration.ServerIP)
	if err != nil {
		return fmt.Errorf("virtual_network.server_ip: %w", err)
	}
	if configuration.PacketChannels < 1 ||
		configuration.PacketChannels > hardMaxVNetPacketChannels {
		return fmt.Errorf(
			"virtual_network.packet_channels must be between 1 and %d",
			hardMaxVNetPacketChannels,
		)
	}
	if len(configuration.Nodes) > hardMaxVNetNodes {
		return fmt.Errorf("virtual_network.nodes must contain at most %d entries", hardMaxVNetNodes)
	}
	if err := validateVNetPorts("virtual_network.server_ports", configuration.ServerPorts); err != nil {
		return err
	}

	clientIDs := make(map[string]struct{}, len(configuration.Nodes))
	addresses := map[netip.Addr]string{serverIP: "server_ip"}
	hasPorts := vnetPortsConfigured(configuration.ServerPorts)
	for index, node := range configuration.Nodes {
		field := fmt.Sprintf("virtual_network.nodes[%d]", index)
		if err := ValidateClientID(node.ClientID); err != nil {
			return fmt.Errorf("%s.client_id: %w", field, err)
		}
		if _, duplicate := clientIDs[node.ClientID]; duplicate {
			return fmt.Errorf("%s.client_id is duplicated", field)
		}
		clientIDs[node.ClientID] = struct{}{}
		address, parseError := parseVNetHost(prefix, node.IP)
		if parseError != nil {
			return fmt.Errorf("%s.ip: %w", field, parseError)
		}
		if owner, duplicate := addresses[address]; duplicate {
			return fmt.Errorf("%s.ip duplicates virtual_network.%s", field, owner)
		}
		addresses[address] = fmt.Sprintf("nodes[%d].ip", index)
		if err := validateVNetPorts(field+".ports", node.Ports); err != nil {
			return err
		}
		hasPorts = hasPorts || vnetPortsConfigured(node.Ports)
	}
	if configuration.Enabled && !hasPorts {
		return errors.New("virtual_network must expose at least one TCP or UDP port when enabled")
	}
	return nil
}

// EffectiveVNetNetworkMode returns the defaulted VNet delivery mode.
func EffectiveVNetNetworkMode(configuration VirtualNetworkConfig) VNetNetworkMode {
	if configuration.NetworkMode == "" {
		return VNetNetworkModeTUN
	}
	return configuration.NetworkMode
}

func validateVirtualNetworkManagedClients(configuration ServerConfig) error {
	for index, node := range configuration.VirtualNetwork.Nodes {
		if _, exists := configuration.ManagedClients[node.ClientID]; !exists {
			return fmt.Errorf(
				"virtual_network.nodes[%d].client_id %q must identify a managed client",
				index,
				node.ClientID,
			)
		}
	}
	return nil
}

// VNetNode returns the server-owned virtual network assignment for one client.
func VNetNode(configuration VirtualNetworkConfig, clientID string) (VNetNodeConfig, bool) {
	for _, node := range configuration.Nodes {
		if node.ClientID == clientID {
			return node, true
		}
	}
	return VNetNodeConfig{}, false
}

func validateVNetPorts(field string, ports VNetPortPermissions) error {
	if err := validateSortedPortRanges(field+".tcp.port_ranges", ports.TCP.PortRanges); err != nil {
		return err
	}
	return validateSortedPortRanges(field+".udp.port_ranges", ports.UDP.PortRanges)
}

func vnetPortsConfigured(ports VNetPortPermissions) bool {
	return len(ports.TCP.PortRanges) != 0 || len(ports.UDP.PortRanges) != 0
}

func parseVNetHost(prefix netip.Prefix, source string) (netip.Addr, error) {
	address, err := netip.ParseAddr(source)
	if err != nil || !address.Is4() || address.String() != source {
		return netip.Addr{}, errors.New("must be a canonical IPv4 address")
	}
	if !prefix.Contains(address) {
		return netip.Addr{}, errors.New("must belong to virtual_network.cidr")
	}
	if address == prefix.Addr() || address == ipv4Broadcast(prefix) {
		return netip.Addr{}, errors.New("must be a usable host address")
	}
	return address, nil
}

func ipv4Broadcast(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Addr().As4()
	hostBits := 32 - prefix.Bits()
	value := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
	value |= uint32(1<<hostBits) - 1
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}
