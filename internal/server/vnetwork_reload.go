package server

import "github.com/acexy/portway/internal/config"

func (s *Service) validateVNetConfigurationTransition(
	current config.VirtualNetworkConfig,
	candidate config.VirtualNetworkConfig,
) error {
	if current.Enabled && current.CIDR != candidate.CIDR {
		return restartRequiredError{field: "virtual_network.cidr"}
	}
	if current.Enabled && current.ServerIP != candidate.ServerIP {
		return restartRequiredError{field: "virtual_network.server_ip"}
	}
	if s.vnetRuntime == nil {
		return nil
	}
	currentNodes := make(map[string]string, len(current.Nodes))
	for _, node := range current.Nodes {
		currentNodes[node.ClientID] = node.IP
	}
	for _, node := range candidate.Nodes {
		if previousIP, exists := currentNodes[node.ClientID]; exists && previousIP != node.IP &&
			s.vnetRuntime.hasSession(node.ClientID) {
			return restartRequiredError{field: "virtual_network.nodes.ip"}
		}
	}
	return nil
}
