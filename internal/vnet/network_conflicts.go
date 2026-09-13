package vnet

import (
	"fmt"
	"net"
	"net/netip"
)

// checkNetworkConflicts runs before creating any interface or connected route.
func checkNetworkConflicts(spec NetworkSpec, routes []netip.Prefix) error {
	return checkNetworkConflictsExcluding(spec, routes, "")
}

func checkNetworkConflictsExcluding(spec NetworkSpec, routes []netip.Prefix, ownedInterface string) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("inspect VNet address conflicts: %w", err)
	}
	var addresses []netip.Prefix
	for _, device := range interfaces {
		if device.Name == ownedInterface {
			continue
		}
		values, err := device.Addrs()
		if err != nil {
			return fmt.Errorf("inspect VNet interface addresses: %w", err)
		}
		for _, value := range values {
			prefix, err := netip.ParsePrefix(value.String())
			if err != nil {
				return fmt.Errorf("inspect VNet interface address: %w", err)
			}
			if prefix.Addr().Is4() {
				addresses = append(addresses, prefix)
			}
		}
	}
	return validateNetworkConflicts(netip.MustParsePrefix(spec.CIDR), addresses, routes)
}

func validateNetworkConflicts(candidate netip.Prefix, addresses, routes []netip.Prefix) error {
	for _, prefix := range addresses {
		if candidate.Overlaps(prefix) {
			return fmt.Errorf("%w: VNet CIDR overlaps an existing interface address", ErrForeignResource)
		}
	}
	for _, prefix := range routes {
		if prefix.Bits() != 0 && candidate.Overlaps(prefix) {
			return fmt.Errorf("%w: VNet CIDR overlaps an existing route", ErrForeignResource)
		}
	}
	return nil
}
