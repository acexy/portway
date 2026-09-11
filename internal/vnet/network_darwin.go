//go:build darwin

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
	if manifestError == nil {
		if manifest.Role != spec.Role || manifest.CIDR != spec.CIDR || manifest.LocalIP != spec.LocalIP || manifest.ServerIP != spec.ServerIP {
			return nil, ErrStateMismatch
		}
		if _, err := net.InterfaceByName(manifest.PlatformInterface); err == nil {
			return nil, fmt.Errorf("%w: recorded macOS utun is owned by another process", ErrForeignResource)
		}
	} else if !errors.Is(manifestError, os.ErrNotExist) {
		return nil, manifestError
	}
	device, err := OpenDevice()
	if err != nil {
		return nil, err
	}
	prefixLength, _ := netipPrefixLength(spec.CIDR)
	if err := privilegedCommand("/sbin/ifconfig", device.Name(), "inet", spec.LocalIP, spec.ServerIP,
		"netmask", cidrNetmask(prefixLength), "mtu", strconv.Itoa(int(spec.MTU)), "up").Run(); err != nil {
		device.Close()
		return nil, fmt.Errorf("configure macOS VNet interface: %w", err)
	}
	if err := privilegedCommand("/sbin/route", "-n", "add", "-net", spec.CIDR, "-interface", device.Name()).Run(); err != nil {
		device.Close()
		return nil, fmt.Errorf("configure macOS VNet route: %w", err)
	}
	if err := installManifest(spec, device.Name()); err != nil {
		device.Close()
		return nil, err
	}
	return lockOwnedDevice(device)
}

func uninstallPlatformNetwork(manifest ownershipManifest) error {
	return privilegedCommand("/sbin/route", "-n", "delete", "-net", manifest.CIDR, "-interface", manifest.PlatformInterface).Run()
}

func repairPlatformNetwork(spec NetworkSpec) (Device, error) {
	return preparePlatformNetwork(spec)
}

func platformRootGroup() string { return "wheel" }

func netipPrefixLength(cidr string) (int, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}
	bits, _ := network.Mask.Size()
	return bits, nil
}

func cidrNetmask(bits int) string {
	mask := net.CIDRMask(bits, 32)
	return net.IP(mask).String()
}
