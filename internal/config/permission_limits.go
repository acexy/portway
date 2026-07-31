package config

import systemlimits "github.com/acexy/portway/internal/limits"

const (
	defaultMaxProxies     = 20
	defaultMaxTCPProxies  = 10
	defaultMaxUDPProxies  = 5
	defaultMaxHTTPProxies = 10
	defaultMaxActiveLinks = 100

	hardMaxProxiesPerClient     = systemlimits.HardMaxProxiesPerClient
	hardMaxActiveLinksPerClient = systemlimits.HardMaxActiveLinksPerClient
)

// DefaultPermissionLimits returns production-safe governed client limits.
func DefaultPermissionLimits() PermissionLimits {
	return PermissionLimits{
		MaxProxies:     defaultMaxProxies,
		MaxTCPProxies:  defaultMaxTCPProxies,
		MaxUDPProxies:  defaultMaxUDPProxies,
		MaxHTTPProxies: defaultMaxHTTPProxies,
		MaxActiveLinks: defaultMaxActiveLinks,
	}
}
