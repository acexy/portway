package server

import "github.com/acexy/portway/internal/config"

func (s *Service) validateVNetConfigurationTransition(
	current config.VirtualNetworkConfig,
	candidate config.VirtualNetworkConfig,
) error {
	if config.EffectiveVNetNetworkMode(current) != config.EffectiveVNetNetworkMode(candidate) {
		return restartRequiredError{field: "virtual_network.network_mode"}
	}
	return nil
}
