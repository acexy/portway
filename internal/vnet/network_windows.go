//go:build windows && amd64

package vnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

func preparePlatformNetwork(ctx context.Context, spec NetworkSpec) (Device, error) {
	dllPath, err := windowsWintunPath()
	if err != nil {
		return nil, err
	}
	return prepareWindowsNetwork(ctx, spec, dllPath)
}

func prepareWindowsNetwork(ctx context.Context, spec NetworkSpec, dllPath string) (Device, error) {
	if !windowsProcessElevated() {
		return nil, errors.New("Windows VNet requires portway to run as administrator")
	}
	routes, err := windowsNetworkRoutes(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkNetworkConflicts(spec, routes); err != nil {
		return nil, err
	}
	if _, err := net.InterfaceByName(LogicalInterfaceName); err == nil {
		// A process-owned Windows adapter must never adopt an existing name.
		return nil, fmt.Errorf("%w: Windows network interface %s already exists", ErrForeignResource, LogicalInterfaceName)
	}
	device, err := createWindowsDeviceFrom(dllPath)
	if err != nil {
		return nil, err
	}
	if err := configureWindowsNetwork(ctx, spec); err != nil {
		_ = device.Close()
		return nil, err
	}
	if err := waitForWindowsNetworkConfiguration(ctx, spec); err != nil {
		_ = device.Close()
		return nil, fmt.Errorf("%w: Windows VNet interface configuration did not converge: %v", ErrStateMismatch, err)
	}
	return device, nil
}

func waitForWindowsNetworkConfiguration(ctx context.Context, spec NetworkSpec) error {
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	var lastError error
	for {
		if err := validateWindowsNetworkConfiguration(ctx, spec); err == nil {
			return nil
		} else {
			lastError = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return lastError
		case <-ticker.C:
		}
	}
}

func configureWindowsNetwork(ctx context.Context, spec NetworkSpec) error {
	prefix, _ := netip.ParsePrefix(spec.CIDR)
	mask := net.CIDRMask(prefix.Bits(), 32)
	maskAddress := net.IP(mask).String()
	commands := [][]string{
		{"interface", "ipv4", "set", "address", "name=" + LogicalInterfaceName,
			"source=static", "address=" + spec.LocalIP, "mask=" + maskAddress,
			"gateway=none", "store=active"},
		{"interface", "ipv4", "set", "subinterface", LogicalInterfaceName,
			fmt.Sprintf("mtu=%d", spec.MTU), "store=active"},
		// Wintun adapters do not consistently receive an automatic on-link route
		// from netsh address assignment. Keep the route in the active store so it
		// disappears with the process-owned adapter or at the next boot.
		{"interface", "ipv4", "add", "route", "prefix=" + prefix.Masked().String(),
			"interface=" + LogicalInterfaceName, "store=active"},
	}
	for _, arguments := range commands {
		output, err := exec.CommandContext(ctx, "netsh", arguments...).CombinedOutput()
		if err != nil {
			message := strings.TrimSpace(string(output))
			if len(message) > 512 {
				message = message[:512]
			}
			return fmt.Errorf("configure Windows VNet network: %w: %s", err, message)
		}
	}
	return nil
}

func windowsProcessElevated() bool {
	procedure := windows.NewLazySystemDLL("shell32.dll").NewProc("IsUserAnAdmin")
	result, _, _ := procedure.Call()
	return result != 0
}

func validateWindowsNetworkConfiguration(ctx context.Context, spec NetworkSpec) error {
	interfaceValue, err := net.InterfaceByName(LogicalInterfaceName)
	if err != nil {
		return fmt.Errorf("interface is unavailable: %w", err)
	}
	mtu, err := windowsInterfaceMTU(ctx, LogicalInterfaceName)
	if err != nil {
		return err
	}
	if mtu != int(spec.MTU) {
		return fmt.Errorf("IPv4 MTU is %d, expected %d", mtu, spec.MTU)
	}
	prefix, err := netip.ParsePrefix(spec.CIDR)
	if err != nil {
		return err
	}
	expected := spec.LocalIP + "/" + fmt.Sprint(prefix.Bits())
	addresses, err := interfaceValue.Addrs()
	if err != nil {
		return err
	}
	for _, address := range addresses {
		if address.String() == expected {
			routes, routeError := windowsNetworkRoutes(ctx)
			if routeError != nil {
				return routeError
			}
			for _, route := range routes {
				if route == prefix.Masked() {
					listener, listenError := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(spec.LocalIP)})
					if listenError != nil {
						return fmt.Errorf("address %s is not ready: %w", spec.LocalIP, listenError)
					}
					return listener.Close()
				}
			}
			return fmt.Errorf("on-link route %s is absent", prefix.Masked())
		}
	}
	return fmt.Errorf("address %s is absent from %v", expected, addresses)
}

func windowsInterfaceMTU(ctx context.Context, interfaceName string) (int, error) {
	data, err := exec.CommandContext(ctx, "netsh", "interface", "ipv4", "show", "subinterfaces").Output()
	if err != nil {
		return 0, fmt.Errorf("inspect Windows IPv4 interface MTU: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[len(fields)-1] != interfaceName {
			continue
		}
		mtu, parseError := strconv.Atoi(fields[0])
		if parseError == nil && mtu > 0 {
			return mtu, nil
		}
	}
	return 0, fmt.Errorf("Windows IPv4 interface %s is absent", interfaceName)
}

func windowsNetworkRoutes(ctx context.Context) ([]netip.Prefix, error) {
	data, err := exec.CommandContext(ctx, "route", "print", "-4").Output()
	if err != nil {
		return nil, fmt.Errorf("inspect Windows IPv4 routes: %w", err)
	}
	return parseWindowsNetworkRoutes(data)
}

func parseWindowsNetworkRoutes(data []byte) ([]netip.Prefix, error) {
	var routes []netip.Prefix
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		destination, destinationError := netip.ParseAddr(fields[0])
		maskAddress, maskError := netip.ParseAddr(fields[1])
		if destinationError != nil || maskError != nil || !destination.Is4() || !maskAddress.Is4() {
			continue
		}
		mask := net.IPMask(maskAddress.AsSlice())
		bits, size := mask.Size()
		if size != 32 {
			return nil, errors.New("invalid Windows IPv4 route mask")
		}
		routes = append(routes, netip.PrefixFrom(destination, bits).Masked())
	}
	return routes, nil
}

func uninstallPlatformNetwork(ownershipManifest) error {
	return errors.New("manual VNet management is unavailable on Windows")
}

func repairPlatformNetwork(spec NetworkSpec) (Device, error) {
	return preparePlatformNetwork(context.Background(), spec)
}

func platformRootGroup() string                      { return "" }
func manualNetworkManagementSupported() bool         { return false }
func runtimeHelperSupported() bool                   { return false }
func platformSupported() bool                        { return true }
func runtimeReprepareSupported() bool                { return windowsProcessElevated() }
func runPlatformHelper([]string) (bool, error)       { return false, nil }
func platformIdentityMatches(ownershipManifest) bool { return false }
