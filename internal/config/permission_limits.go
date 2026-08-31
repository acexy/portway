package config

import systemlimits "github.com/acexy/portway/internal/limits"

const (
	defaultMaxProxies            = 20
	defaultMaxTCPProxies         = 10
	defaultMaxUDPProxies         = 5
	defaultMaxHTTPProxies        = 10
	defaultMaxActiveLinks        = 100
	defaultMaxForwards           = 20
	defaultMaxTCPForwards        = 10
	defaultMaxUDPForwards        = 5
	defaultMaxActiveForwardLinks = 100

	hardMaxProxiesPerClient     = systemlimits.HardMaxProxiesPerClient
	hardMaxActiveLinksPerClient = systemlimits.HardMaxActiveLinksPerClient
)

// DefaultProxyPermissionLimits returns production-safe Proxy ceilings.
func DefaultProxyPermissionLimits() ProxyPermissionLimits {
	return ProxyPermissionLimits{
		MaxTotal: defaultMaxProxies, MaxTCP: defaultMaxTCPProxies,
		MaxUDP: defaultMaxUDPProxies, MaxHTTP: defaultMaxHTTPProxies,
		MaxActiveLinks: defaultMaxActiveLinks,
	}
}

// DefaultForwardPermissionLimits returns production-safe Forward ceilings.
func DefaultForwardPermissionLimits() ForwardPermissionLimits {
	return ForwardPermissionLimits{
		MaxTotal: defaultMaxForwards, MaxTCP: defaultMaxTCPForwards,
		MaxUDP: defaultMaxUDPForwards, MaxActiveLinks: defaultMaxActiveForwardLinks,
	}
}
