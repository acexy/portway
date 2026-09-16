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
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const windowsNetworkLockName = `Global\PortwayVNetwork-portway0`

var windowsNetworkClassGUID = windows.GUID{
	Data1: 0x4d36e972,
	Data2: 0xe325,
	Data3: 0x11ce,
	Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18},
}

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
	networkLock, inUse, err := acquireWindowsNetworkLock()
	if err != nil {
		return nil, err
	}
	if inUse {
		_ = windows.CloseHandle(networkLock)
		return nil, errors.New("Windows VNet network is in use")
	}
	releaseNetworkLock := true
	defer func() {
		if releaseNetworkLock {
			_ = windows.ReleaseMutex(networkLock)
			_ = windows.CloseHandle(networkLock)
		}
	}()
	if _, interfaceError := net.InterfaceByName(LogicalInterfaceName); interfaceError == nil {
		removed, removeError := removeWindowsNetworkAdapter()
		if removeError != nil {
			return nil, removeError
		}
		if !removed {
			return nil, fmt.Errorf("remove existing Windows network interface %s", LogicalInterfaceName)
		}
		if err := waitForWindowsNetworkRemoval(ctx); err != nil {
			return nil, err
		}
	}
	routes, err := windowsNetworkRoutes(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkNetworkConflicts(spec, routes); err != nil {
		return nil, err
	}
	device, err := createWindowsDeviceWithLock(dllPath, networkLock)
	if err != nil {
		return nil, err
	}
	releaseNetworkLock = false
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

func waitForWindowsNetworkRemoval(ctx context.Context) error {
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := net.InterfaceByName(LogicalInterfaceName); err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("Windows network interface %s was not removed", LogicalInterfaceName)
		case <-ticker.C:
		}
	}
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

func migrateWindowsNetwork(ctx context.Context, previous, next NetworkSpec) (result error) {
	if previous.CIDR == next.CIDR && previous.LocalIP == next.LocalIP && previous.MTU == next.MTU {
		return validateWindowsNetworkConfiguration(ctx, next)
	}
	if err := validateWindowsNetworkConfiguration(ctx, previous); err != nil {
		return fmt.Errorf("validate previous Windows VNet configuration: %w", err)
	}
	if err := deleteWindowsNetworkRoute(ctx, previous); err != nil {
		return err
	}
	defer func() {
		if result == nil {
			return
		}
		rollbackContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = deleteWindowsNetworkRoute(rollbackContext, next)
		if rollbackError := configureWindowsNetwork(rollbackContext, previous); rollbackError != nil {
			result = errors.Join(result, fmt.Errorf("restore previous Windows VNet configuration: %w", rollbackError))
			return
		}
		if rollbackError := validateWindowsNetworkConfiguration(rollbackContext, previous); rollbackError != nil {
			result = errors.Join(result, fmt.Errorf("validate restored Windows VNet configuration: %w", rollbackError))
		}
	}()
	if err := configureWindowsNetwork(ctx, next); err != nil {
		return err
	}
	if err := waitForWindowsNetworkConfiguration(ctx, next); err != nil {
		return err
	}
	return nil
}

func deleteWindowsNetworkRoute(ctx context.Context, spec NetworkSpec) error {
	prefix, _ := netip.ParsePrefix(spec.CIDR)
	output, err := exec.CommandContext(
		ctx,
		"netsh",
		"interface",
		"ipv4",
		"delete",
		"route",
		"prefix="+prefix.Masked().String(),
		"interface="+LogicalInterfaceName,
		"store=active",
	).CombinedOutput()
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(output))
	if len(message) > 512 {
		message = message[:512]
	}
	return fmt.Errorf("remove previous Windows VNet route: %w: %s", err, message)
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

func acquireWindowsNetworkLock() (windows.Handle, bool, error) {
	name, err := windows.UTF16PtrFromString(windowsNetworkLockName)
	if err != nil {
		return 0, false, err
	}
	handle, err := windows.CreateMutex(nil, true, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return handle, true, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("acquire Windows VNet ownership lock: %w", err)
	}
	return handle, false, nil
}

func uninstallEphemeralNetwork() (string, bool, error) {
	if !windowsProcessElevated() {
		return "PermissionDenied", true, errors.New("Windows VNet uninstall requires administrator privileges")
	}
	lock, inUse, err := acquireWindowsNetworkLock()
	if err != nil {
		return "StateMismatch", true, err
	}
	if inUse {
		_ = windows.CloseHandle(lock)
		return "InUse", true, errors.New("VNet network is in use")
	}
	defer windows.CloseHandle(lock)
	defer windows.ReleaseMutex(lock)

	removed, err := removeWindowsNetworkAdapter()
	if err != nil {
		if errors.Is(err, ErrForeignResource) {
			return "ForeignResource", true, err
		}
		return "PartialFailure", true, err
	}
	if !removed {
		return "AlreadyAbsent", true, nil
	}
	return "Removed", true, nil
}

func removeWindowsNetworkAdapter() (bool, error) {
	interfaceGUID, found, err := windowsInterfaceGUID(LogicalInterfaceName)
	if err != nil || !found {
		return false, err
	}
	if err := validateWindowsAdapterGUID(interfaceGUID); err != nil {
		return false, err
	}
	deviceInformation, err := windows.SetupDiGetClassDevsEx(
		&windowsNetworkClassGUID,
		"",
		0,
		windows.DIGCF_PRESENT,
		0,
		"",
	)
	if err != nil {
		return false, fmt.Errorf("enumerate Windows network adapters: %w", err)
	}
	defer deviceInformation.Close()

	for index := 0; ; index++ {
		device, enumerateError := deviceInformation.EnumDeviceInfo(index)
		if errors.Is(enumerateError, windows.ERROR_NO_MORE_ITEMS) {
			return false, nil
		}
		if enumerateError != nil {
			continue
		}
		keyHandle, openError := deviceInformation.OpenDevRegKey(
			device,
			windows.DICS_FLAG_GLOBAL,
			0,
			windows.DIREG_DRV,
			windows.KEY_QUERY_VALUE,
		)
		if openError != nil {
			continue
		}
		key := registry.Key(keyHandle)
		identifier, _, identifierError := key.GetStringValue("NetCfgInstanceId")
		_ = key.Close()
		if identifierError != nil {
			continue
		}
		adapterGUID, parseError := windows.GUIDFromString(identifier)
		if parseError != nil || adapterGUID != interfaceGUID {
			continue
		}

		parameters := windows.RemoveDeviceParams{
			ClassInstallHeader: *windows.MakeClassInstallHeader(windows.DIF_REMOVE),
			Scope:              windows.DI_REMOVEDEVICE_GLOBAL,
		}
		if err := deviceInformation.SetClassInstallParams(
			device,
			&parameters.ClassInstallHeader,
			uint32(unsafe.Sizeof(parameters)),
		); err != nil {
			return false, fmt.Errorf("configure Windows VNet adapter removal: %w", err)
		}
		if err := deviceInformation.CallClassInstaller(windows.DIF_REMOVE, device); err != nil {
			return false, fmt.Errorf("remove Windows VNet adapter: %w", err)
		}
		return true, nil
	}
}

func validateWindowsAdapterGUID(interfaceGUID windows.GUID) error {
	if interfaceGUID != windowsAdapterGUID {
		return fmt.Errorf("%w: interface %s is not the Portway adapter", ErrForeignResource, LogicalInterfaceName)
	}
	return nil
}

func windowsInterfaceGUID(interfaceName string) (windows.GUID, bool, error) {
	bufferSize := uint32(15 * 1024)
	for {
		buffer := make([]byte, bufferSize)
		addresses := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(
			windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_UNICAST|windows.GAA_FLAG_SKIP_ANYCAST|
				windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0,
			addresses,
			&bufferSize,
		)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return windows.GUID{}, false, fmt.Errorf("inspect Windows network interfaces: %w", err)
		}
		for address := addresses; address != nil; address = address.Next {
			if windows.UTF16PtrToString(address.FriendlyName) == interfaceName {
				return address.NetworkGuid, true, nil
			}
		}
		return windows.GUID{}, false, nil
	}
}

func uninstallPlatformNetwork(ownershipManifest) error {
	return errors.New("Windows VNet does not use persistent network manifests")
}

func repairPlatformNetwork(spec NetworkSpec) (Device, error) {
	return preparePlatformNetwork(context.Background(), spec)
}

func platformRootGroup() string                      { return "" }
func manualNetworkManagementSupported() bool         { return false }
func networkUninstallSupported() bool                 { return true }
func runtimeHelperSupported() bool                   { return false }
func platformSupported() bool                        { return true }
func runtimeReprepareSupported() bool                { return windowsProcessElevated() }
func runPlatformHelper(arguments []string) (bool, error) {
	return runWindowsElevationHelper(arguments)
}
func platformIdentityMatches(ownershipManifest) bool { return false }
