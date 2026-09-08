package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/acexy/portway/internal/protocol"
)

func validateGovernedPermissions(permissions GovernedPermissions) error {
	proxies := permissions.Proxies
	if proxies.TCP != nil {
		if err := validateSortedPortRanges(
			"permissions.proxies.tcp.port_ranges",
			proxies.TCP.PortRanges,
		); err != nil {
			return err
		}
		if len(proxies.TCP.PortRanges) == 0 {
			return errors.New("permissions.proxies.tcp.port_ranges must not be empty")
		}
	}
	if proxies.UDP != nil {
		if err := validateSortedPortRanges(
			"permissions.proxies.udp.port_ranges",
			proxies.UDP.PortRanges,
		); err != nil {
			return err
		}
		if len(proxies.UDP.PortRanges) == 0 {
			return errors.New("permissions.proxies.udp.port_ranges must not be empty")
		}
	}
	if err := validateForwardRules("permissions.forwards.rules", permissions.Forwards.Rules); err != nil {
		return err
	}
	if proxies.HTTP == nil {
		return validateGovernedLimits(permissions)
	}
	if len(proxies.HTTP.Domains) == 0 {
		return errors.New("permissions.proxies.http.domains must not be empty")
	}
	domains := make(map[string]struct{}, len(proxies.HTTP.Domains))
	for index, domain := range proxies.HTTP.Domains {
		if strings.HasPrefix(domain, "*.") {
			if err := ValidateHTTPDomain(strings.TrimPrefix(domain, "*.")); err != nil {
				return fmt.Errorf("permissions.proxies.http.domains[%d]: invalid wildcard domain", index)
			}
		} else if err := ValidateHTTPDomain(domain); err != nil {
			return fmt.Errorf("permissions.proxies.http.domains[%d]: %w", index, err)
		}
		if _, duplicate := domains[domain]; duplicate {
			return fmt.Errorf("permissions.proxies.http.domains contains duplicate domain %q", domain)
		}
		domains[domain] = struct{}{}
	}
	if len(proxies.HTTP.PublicSchemes) > 0 {
		if err := validateHTTPPublicSchemes(
			proxies.HTTP.PublicSchemes,
			"permissions.proxies.http.public_schemes",
		); err != nil {
			return err
		}
	}
	return validateGovernedLimits(permissions)
}

func validateGovernedLimits(permissions GovernedPermissions) error {
	proxyLimits := permissions.Proxies.Limits
	for _, limit := range []struct {
		name  string
		value int
		max   int
	}{
		{"max_total", proxyLimits.MaxTotal, hardMaxProxiesPerClient},
		{"max_tcp", proxyLimits.MaxTCP, hardMaxProxiesPerClient},
		{"max_udp", proxyLimits.MaxUDP, hardMaxProxiesPerClient},
		{"max_http", proxyLimits.MaxHTTP, hardMaxProxiesPerClient},
		{"max_active_links", proxyLimits.MaxActiveLinks, hardMaxActiveLinksPerClient},
	} {
		if limit.value <= 0 || limit.value > limit.max {
			return fmt.Errorf(
				"permissions.proxies.limits.%s must be greater than zero and at most %d",
				limit.name,
				limit.max,
			)
		}
	}
	if proxyLimits.MaxTCP > proxyLimits.MaxTotal || proxyLimits.MaxUDP > proxyLimits.MaxTotal ||
		proxyLimits.MaxHTTP > proxyLimits.MaxTotal {
		return errors.New("permissions.proxies per-type limits must not exceed max_total")
	}
	forwardLimits := permissions.Forwards.Limits
	for _, limit := range []struct {
		name  string
		value int
		max   int
	}{
		{"max_total", forwardLimits.MaxTotal, hardMaxProxiesPerClient},
		{"max_tcp", forwardLimits.MaxTCP, hardMaxProxiesPerClient},
		{"max_udp", forwardLimits.MaxUDP, hardMaxProxiesPerClient},
		{"max_active_links", forwardLimits.MaxActiveLinks, hardMaxActiveLinksPerClient},
	} {
		if limit.value <= 0 || limit.value > limit.max {
			return fmt.Errorf(
				"permissions.forwards.limits.%s must be greater than zero and at most %d",
				limit.name,
				limit.max,
			)
		}
	}
	if forwardLimits.MaxTCP > forwardLimits.MaxTotal || forwardLimits.MaxUDP > forwardLimits.MaxTotal {
		return errors.New("permissions.forwards per-type limits must not exceed max_total")
	}
	return nil
}

func applyGovernedPermissionDefaults(permissions *GovernedPermissions) {
	if permissions.Proxies.HTTP == nil || len(permissions.Proxies.HTTP.PublicSchemes) != 0 {
		return
	}
	permissions.Proxies.HTTP.PublicSchemes = []protocol.HTTPPublicScheme{
		protocol.HTTPPublicSchemeHTTP,
	}
}
