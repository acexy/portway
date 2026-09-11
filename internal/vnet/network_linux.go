//go:build linux

package vnet

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
)

func preparePlatformNetwork(spec NetworkSpec) (Device, error) {
	manifest, manifestError := readManifest()
	_, interfaceError := net.InterfaceByName(LogicalInterfaceName)
	if errors.Is(manifestError, os.ErrNotExist) && interfaceError == nil {
		return nil, ErrForeignResource
	}
	if manifestError == nil {
		if manifest.Role != spec.Role || manifest.CIDR != spec.CIDR || manifest.LocalIP != spec.LocalIP ||
			manifest.ServerIP != spec.ServerIP || manifest.PlatformInterface != LogicalInterfaceName {
			return nil, ErrStateMismatch
		}
		if interfaceError != nil {
			return nil, ErrStateMismatch
		}
		if !interfaceMatchesManifest(manifest) {
			return nil, ErrStateMismatch
		}
		return OpenInstalledNetwork()
	}
	if !errors.Is(manifestError, os.ErrNotExist) {
		return nil, manifestError
	}
	owner := spec.OwnerUID
	if owner < 0 {
		owner = os.Getuid()
	}
	if err := privilegedCommand("ip", "tuntap", "add", "dev", LogicalInterfaceName, "mode", "tun", "user", strconv.Itoa(owner)).Run(); err != nil {
		return nil, fmt.Errorf("create Linux VNet interface: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = privilegedCommand("ip", "link", "delete", "dev", LogicalInterfaceName).Run()
		}
	}()
	prefixLength, _ := netipPrefixLength(spec.CIDR)
	if err := privilegedCommand("ip", "address", "add", spec.LocalIP+"/"+strconv.Itoa(prefixLength), "dev", LogicalInterfaceName).Run(); err != nil {
		return nil, fmt.Errorf("configure Linux VNet address: %w", err)
	}
	if err := privilegedCommand("ip", "link", "set", "dev", LogicalInterfaceName, "mtu", strconv.Itoa(int(spec.MTU)), "up").Run(); err != nil {
		return nil, fmt.Errorf("activate Linux VNet interface: %w", err)
	}
	if err := installManifest(spec, LogicalInterfaceName); err != nil {
		return nil, err
	}
	device, err := OpenInstalledNetwork()
	if err != nil {
		return nil, err
	}
	rollback = false
	return device, nil
}

func uninstallPlatformNetwork(manifest ownershipManifest) error {
	return privilegedCommand("ip", "link", "delete", "dev", manifest.PlatformInterface).Run()
}

func repairPlatformNetwork(spec NetworkSpec) (Device, error) {
	manifest, err := readManifest()
	if errors.Is(err, os.ErrNotExist) {
		return preparePlatformNetwork(spec)
	}
	if err != nil || manifest.Role != spec.Role || manifest.CIDR != spec.CIDR ||
		manifest.LocalIP != spec.LocalIP || manifest.ServerIP != spec.ServerIP ||
		manifest.PlatformInterface != LogicalInterfaceName {
		return nil, ErrStateMismatch
	}
	if _, err := net.InterfaceByName(LogicalInterfaceName); err == nil {
		prefixLength, _ := netipPrefixLength(spec.CIDR)
		if err := privilegedCommand("ip", "address", "replace", spec.LocalIP+"/"+strconv.Itoa(prefixLength), "dev", LogicalInterfaceName).Run(); err != nil {
			return nil, fmt.Errorf("repair Linux VNet address: %w", err)
		}
		if err := privilegedCommand("ip", "link", "set", "dev", LogicalInterfaceName, "mtu", strconv.Itoa(int(spec.MTU)), "up").Run(); err != nil {
			return nil, fmt.Errorf("repair Linux VNet interface: %w", err)
		}
		return OpenInstalledNetwork()
	}
	if err := privilegedCommand("rm", manifestPath()).Run(); err != nil {
		return nil, fmt.Errorf("remove stale VNet ownership manifest: %w", err)
	}
	return preparePlatformNetwork(spec)
}

func platformRootGroup() string { return "root" }

func netipPrefixLength(cidr string) (int, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}
	bits, _ := network.Mask.Size()
	return bits, nil
}
