//go:build linux

package vnet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"time"
)

func preparePlatformNetwork(ctx context.Context, spec NetworkSpec) (Device, error) {
	if err := ensureLinuxNetwork(ctx, spec); err != nil {
		return nil, err
	}
	return OpenInstalledNetwork()
}

func ensureLinuxNetwork(ctx context.Context, spec NetworkSpec) error {
	manifest, manifestError := readManifest()
	_, interfaceError := net.InterfaceByName(LogicalInterfaceName)
	if errors.Is(manifestError, os.ErrNotExist) {
		if interfaceError == nil {
			return ErrForeignResource
		}
		return installLinuxNetwork(ctx, spec)
	}
	if manifestError != nil {
		return manifestError
	}
	if manifest.Role != spec.Role || manifest.PlatformInterface != LogicalInterfaceName {
		return ErrStateMismatch
	}
	if interfaceError == nil && networkSpecMatchesManifest(spec, manifest) && interfaceMatchesManifest(manifest) {
		return nil
	}
	// Configuration replacement must not alter an interface held by another runtime.
	lock, err := os.Open(manifestPath())
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lockNetworkFile(lock, true); err != nil {
		return fmt.Errorf("VNet network is in use: %w", err)
	}
	defer unlockNetworkFile(lock)
	current, err := readManifest()
	if err != nil || current != manifest {
		return ErrStateMismatch
	}
	if _, err := net.InterfaceByName(LogicalInterfaceName); err != nil {
		return installLinuxNetwork(ctx, spec)
	}
	identity, err := exec.CommandContext(ctx, "ip", "-d", "-j", "link", "show", "dev", LogicalInterfaceName).Output()
	if err != nil || !linuxIdentityCanBeInstalled(identity, manifest) || !interfaceConfigurationMatches(manifest) {
		return ErrForeignResource
	}
	if !networkSpecMatchesManifest(spec, manifest) {
		routes, err := linuxNetworkRoutesExcluding(ctx, LogicalInterfaceName)
		if err != nil {
			return err
		}
		if err := checkNetworkConflictsExcluding(spec, routes, LogicalInterfaceName); err != nil {
			return err
		}
		return migrateLinuxNetwork(ctx, manifest, spec)
	}
	// A legacy installation is adopted only after validating the complete old state.
	return privilegedCommandContext(ctx, "ip", "link", "set", "dev", LogicalInterfaceName,
		"alias", "portway:"+manifest.InstallationID).Run()
}

func installLinuxNetwork(ctx context.Context, spec NetworkSpec) error {
	routes, err := linuxNetworkRoutes(ctx)
	if err != nil {
		return err
	}
	if err := checkNetworkConflicts(spec, routes); err != nil {
		return err
	}
	identifierBytes := make([]byte, 16)
	if _, err := rand.Read(identifierBytes); err != nil {
		return err
	}
	identifier := hex.EncodeToString(identifierBytes)
	owner := spec.OwnerUID
	if owner < 0 {
		owner = os.Getuid()
	}
	if err := privilegedCommandContext(ctx, "ip", "tuntap", "add", "dev", LogicalInterfaceName, "mode", "tun", "user", strconv.Itoa(owner)).Run(); err != nil {
		return fmt.Errorf("create Linux VNet interface: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := privilegedCommandContext(cleanupContext, "ip", "link", "delete", "dev", LogicalInterfaceName).Run(); err == nil {
				if manifest, err := readManifest(); err == nil && manifest.InstallationID == identifier {
					_ = privilegedCommandContext(cleanupContext, "rm", manifestPath()).Run()
				}
			}
		}
	}()
	if err := addLinuxNetworkAddress(ctx, spec); err != nil {
		return err
	}
	if err := setLinuxNetworkIdentity(ctx, spec, identifier); err != nil {
		return err
	}
	if err := installManifest(ctx, spec, LogicalInterfaceName, identifier); err != nil {
		return err
	}
	rollback = false
	return nil
}

func migrateLinuxNetwork(ctx context.Context, manifest ownershipManifest, spec NetworkSpec) error {
	return migrateNetworkInstallation(ctx, manifest, spec, networkMigrationOperations{
		removeAddress: deleteLinuxNetworkAddress,
		addAddress:    addLinuxNetworkAddress,
		setIdentity:   setLinuxNetworkIdentity,
		store: func(ctx context.Context, spec NetworkSpec, identifier string) error {
			return installManifest(ctx, spec, LogicalInterfaceName, identifier)
		},
	})
}

func addLinuxNetworkAddress(ctx context.Context, spec NetworkSpec) error {
	return privilegedCommandContext(ctx, "ip", "address", "add", linuxNetworkAddress(spec), "dev", LogicalInterfaceName).Run()
}

func deleteLinuxNetworkAddress(ctx context.Context, spec NetworkSpec) error {
	return privilegedCommandContext(ctx, "ip", "address", "del", linuxNetworkAddress(spec), "dev", LogicalInterfaceName).Run()
}

func linuxNetworkAddress(spec NetworkSpec) string {
	bits, _ := netipPrefixLength(spec.CIDR)
	return spec.LocalIP + "/" + strconv.Itoa(bits)
}

func setLinuxNetworkIdentity(ctx context.Context, spec NetworkSpec, identifier string) error {
	return privilegedCommandContext(ctx, "ip", "link", "set", "dev", LogicalInterfaceName,
		"alias", "portway:"+identifier, "mtu", strconv.Itoa(int(spec.MTU)), "up").Run()
}

func uninstallPlatformNetwork(manifest ownershipManifest) error {
	return privilegedCommand("ip", "link", "delete", "dev", manifest.PlatformInterface).Run()
}

func repairPlatformNetwork(spec NetworkSpec) (Device, error) {
	return preparePlatformNetwork(context.Background(), spec)
}

func platformRootGroup() string { return "root" }

func manualNetworkManagementSupported() bool { return true }
func networkUninstallSupported() bool         { return true }
func runtimeHelperSupported() bool           { return false }
func platformSupported() bool                { return true }
func runtimeReprepareSupported() bool        { return false }

func runPlatformHelper([]string) (bool, error) { return false, nil }

func uninstallEphemeralNetwork() (string, bool, error) { return "", false, nil }

func netipPrefixLength(cidr string) (int, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}
	bits, _ := network.Mask.Size()
	return bits, nil
}

func linuxNetworkRoutes(ctx context.Context) ([]netip.Prefix, error) {
	return linuxNetworkRoutesExcluding(ctx, "")
}

func linuxNetworkRoutesExcluding(ctx context.Context, ownedInterface string) ([]netip.Prefix, error) {
	data, err := exec.CommandContext(ctx, "ip", "-j", "-4", "route", "show", "table", "all").Output()
	if err != nil {
		return nil, fmt.Errorf("inspect Linux VNet routes: %w", err)
	}
	return parseLinuxNetworkRoutesExcluding(data, ownedInterface)
}

func parseLinuxNetworkRoutes(data []byte) ([]netip.Prefix, error) {
	return parseLinuxNetworkRoutesExcluding(data, "")
}

func parseLinuxNetworkRoutesExcluding(data []byte, ownedInterface string) ([]netip.Prefix, error) {
	var entries []struct {
		Destination string `json:"dst"`
		Device      string `json:"dev"`
		Protocol    string `json:"protocol"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	var routes []netip.Prefix
	for _, entry := range entries {
		if ownedInterface != "" && entry.Device == ownedInterface {
			if entry.Protocol != "kernel" {
				return nil, fmt.Errorf("%w: VNet interface has an unmanaged route", ErrStateMismatch)
			}
			continue
		}
		if entry.Destination == "default" {
			continue
		}
		prefix, err := netip.ParsePrefix(entry.Destination)
		if err != nil {
			address, addressError := netip.ParseAddr(entry.Destination)
			if addressError != nil || !address.Is4() {
				return nil, errors.New("invalid Linux IPv4 route")
			}
			prefix = netip.PrefixFrom(address, 32)
		}
		routes = append(routes, prefix)
	}
	return routes, nil
}

type linuxInterfaceIdentity struct {
	Name     string `json:"ifname"`
	Alias    string `json:"ifalias"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
		Data struct {
			Type string `json:"type"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

func linuxIdentityMatches(data []byte, manifest ownershipManifest) bool {
	return linuxIdentityValid(data, manifest, false)
}

func linuxIdentityCanBeInstalled(data []byte, manifest ownershipManifest) bool {
	return linuxIdentityValid(data, manifest, true)
}

func linuxIdentityValid(data []byte, manifest ownershipManifest, allowLegacy bool) bool {
	var entries []linuxInterfaceIdentity
	return json.Unmarshal(data, &entries) == nil && len(entries) == 1 &&
		entries[0].Name == LogicalInterfaceName && manifest.PlatformInterface == LogicalInterfaceName &&
		(entries[0].Alias == "portway:"+manifest.InstallationID || allowLegacy && entries[0].Alias == "") &&
		entries[0].LinkInfo.Kind == "tun" &&
		entries[0].LinkInfo.Data.Type == "tun"
}

func platformIdentityMatches(manifest ownershipManifest) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, "ip", "-d", "-j", "link", "show", "dev", LogicalInterfaceName).Output()
	return err == nil && linuxIdentityMatches(data, manifest)
}
