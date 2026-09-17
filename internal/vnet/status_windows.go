//go:build windows && amd64

package vnet

import (
	"fmt"
	"net"
	"net/netip"
)

func networkStatusSupported() bool { return true }

func inspectEphemeralNetwork() (NetworkStatus, bool, error) {
	interfaceGUID, found, err := windowsInterfaceGUID(LogicalInterfaceName)
	if err != nil {
		return NetworkStatus{}, true, err
	}
	if !found {
		return NetworkStatus{}, true, nil
	}
	if err := validateWindowsAdapterGUID(interfaceGUID); err != nil {
		return NetworkStatus{}, true, err
	}
	interfaceValue, err := net.InterfaceByName(LogicalInterfaceName)
	if err != nil {
		return NetworkStatus{}, true, fmt.Errorf("%w: interface %s is unavailable: %v", ErrStateMismatch, LogicalInterfaceName, err)
	}
	addresses, err := interfaceValue.Addrs()
	if err != nil {
		return NetworkStatus{}, true, fmt.Errorf("inspect Windows VNet addresses: %w", err)
	}
	cidr, localIP, err := windowsStatusIPv4(addresses)
	if err != nil {
		return NetworkStatus{}, true, err
	}
	return NetworkStatus{
		Installed: true, InterfaceName: LogicalInterfaceName, CIDR: cidr, LocalIP: localIP,
	}, true, nil
}

func windowsStatusIPv4(addresses []net.Addr) (cidr string, localIP string, err error) {
	for _, address := range addresses {
		prefix, parseError := netip.ParsePrefix(address.String())
		if parseError != nil || !prefix.Addr().Is4() {
			continue
		}
		if localIP != "" {
			return "", "", fmt.Errorf("%w: interface %s has multiple IPv4 addresses", ErrStateMismatch, LogicalInterfaceName)
		}
		localIP = prefix.Addr().String()
		cidr = prefix.Masked().String()
	}
	return cidr, localIP, nil
}
