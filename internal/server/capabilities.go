package server

import (
	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
)

func (s *Service) negotiateCapabilities(
	clientCapabilities []protocol.Capability,
	authenticationContext authentication.Context,
) []protocol.Capability {
	supported := map[protocol.Capability]struct{}{
		protocol.CapabilityTCP:         {},
		protocol.CapabilityUDP:         {},
		protocol.CapabilityHTTP:        {},
		protocol.CapabilityJSONControl: {},
	}
	forwardConfiguration := s.configuration.snapshot().Forwards
	for _, rule := range forwardConfiguration.Rules {
		if len(rule.TCP.PortRanges) != 0 {
			supported[protocol.CapabilityTCPForward] = struct{}{}
		}
		if len(rule.UDP.PortRanges) != 0 {
			supported[protocol.CapabilityUDPForward] = struct{}{}
		}
	}
	virtualNetwork := s.configuration.snapshot().VirtualNetwork
	networkMode := config.EffectiveVNetNetworkMode(virtualNetwork)
	if authenticationContext.Mode == authentication.ModeManaged {
		if _, configured := config.VNetNode(virtualNetwork, authenticationContext.ClientID); configured {
			loopbackSupported := coll.SliceContains(
				clientCapabilities,
				protocol.CapabilityVNetLoopback,
			)
			if networkMode != config.VNetNetworkModeLoopback || loopbackSupported {
				supported[protocol.CapabilityVNetIPv4] = struct{}{}
			}
			if networkMode == config.VNetNetworkModeLoopback && loopbackSupported {
				supported[protocol.CapabilityVNetLoopback] = struct{}{}
			}
		}
	}
	negotiated := coll.SliceFilter(
		clientCapabilities,
		func(capability protocol.Capability) bool {
			_, supportedCapability := supported[capability]
			return supportedCapability
		},
	)
	if negotiated == nil {
		return []protocol.Capability{}
	}
	return negotiated
}
