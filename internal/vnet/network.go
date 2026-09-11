package vnet

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

const (
	LogicalInterfaceName = "portway0"
	manifestSchema       = 1
)

var (
	ErrForeignResource = errors.New("foreign VNet resource")
	ErrStateMismatch   = errors.New("VNet state does not match its ownership manifest")
)

type NetworkRole string

const (
	NetworkRoleClient NetworkRole = "client"
	NetworkRoleServer NetworkRole = "server"
)

type NetworkSpec struct {
	Role     NetworkRole
	CIDR     string
	LocalIP  string
	ServerIP string
	MTU      uint16
	OwnerUID int
}

type NetworkStatus struct {
	Installed     bool
	InterfaceName string
	CIDR          string
	LocalIP       string
}

type ownershipManifest struct {
	SchemaVersion     int         `json:"schema_version"`
	InstallationID    string      `json:"installation_id"`
	Role              NetworkRole `json:"role"`
	LogicalName       string      `json:"logical_name"`
	PlatformInterface string      `json:"platform_interface"`
	CIDR              string      `json:"cidr"`
	LocalIP           string      `json:"local_ip"`
	ServerIP          string      `json:"server_ip"`
	MTU               uint16      `json:"mtu"`
}

type ownedDevice struct {
	Device
	lock      *os.File
	closeOnce sync.Once
	closeErr  error
}

func (device *ownedDevice) Close() error {
	device.closeOnce.Do(func() {
		deviceError := device.Device.Close()
		_ = unlockNetworkFile(device.lock)
		lockError := device.lock.Close()
		if deviceError != nil {
			device.closeErr = deviceError
		} else {
			device.closeErr = lockError
		}
	})
	return device.closeErr
}

func PrepareNetwork(spec NetworkSpec) (Device, error) {
	if err := validateNetworkSpec(spec); err != nil {
		return nil, err
	}
	return preparePlatformNetwork(spec)
}

func RepairNetwork(spec NetworkSpec) (Device, error) {
	if err := validateNetworkSpec(spec); err != nil {
		return nil, err
	}
	return repairPlatformNetwork(spec)
}

func InspectNetwork() (NetworkStatus, error) {
	manifest, err := readManifest()
	if errors.Is(err, os.ErrNotExist) {
		return NetworkStatus{}, nil
	}
	if err != nil {
		return NetworkStatus{}, err
	}
	if _, err := net.InterfaceByName(manifest.PlatformInterface); err != nil {
		return NetworkStatus{}, fmt.Errorf("%w: interface %s is missing", ErrStateMismatch, manifest.PlatformInterface)
	}
	if !interfaceMatchesManifest(manifest) {
		return NetworkStatus{}, fmt.Errorf("%w: interface configuration drifted", ErrStateMismatch)
	}
	return NetworkStatus{true, manifest.PlatformInterface, manifest.CIDR, manifest.LocalIP}, nil
}

func UninstallNetwork() (string, error) {
	manifest, err := readManifest()
	if errors.Is(err, os.ErrNotExist) {
		if _, interfaceError := net.InterfaceByName(LogicalInterfaceName); interfaceError == nil {
			return "ForeignResource", ErrForeignResource
		}
		return "AlreadyAbsent", nil
	}
	if err != nil {
		return "StateMismatch", err
	}
	lock, err := os.Open(manifestPath())
	if err != nil {
		return "StateMismatch", err
	}
	defer lock.Close()
	if err := lockNetworkFile(lock, true); err != nil {
		return "InUse", fmt.Errorf("VNet network is in use")
	}
	defer unlockNetworkFile(lock)
	if _, err := net.InterfaceByName(manifest.PlatformInterface); err != nil {
		return "StateMismatch", fmt.Errorf("%w: interface %s is missing", ErrStateMismatch, manifest.PlatformInterface)
	}
	if !interfaceMatchesManifest(manifest) {
		return "StateMismatch", fmt.Errorf("%w: interface configuration drifted", ErrStateMismatch)
	}
	if err := uninstallPlatformNetwork(manifest); err != nil {
		return "PartialFailure", err
	}
	if err := privilegedCommand("rm", manifestPath()).Run(); err != nil {
		return "PartialFailure", fmt.Errorf("remove VNet ownership manifest: %w", err)
	}
	return "Removed", nil
}

func OpenInstalledNetwork() (Device, error) {
	device, err := OpenDevice()
	if err != nil {
		return nil, err
	}
	return lockOwnedDevice(device)
}

func lockOwnedDevice(device Device) (Device, error) {
	lock, err := os.Open(manifestPath())
	if err != nil {
		device.Close()
		return nil, err
	}
	if err := lockNetworkFile(lock, false); err != nil {
		lock.Close()
		device.Close()
		return nil, fmt.Errorf("lock VNet ownership manifest: %w", err)
	}
	return &ownedDevice{Device: device, lock: lock}, nil
}

func installManifest(spec NetworkSpec, interfaceName string) error {
	identifier := make([]byte, 16)
	if _, err := rand.Read(identifier); err != nil {
		return err
	}
	manifest := ownershipManifest{manifestSchema, hex.EncodeToString(identifier), spec.Role,
		LogicalInterfaceName, interfaceName, spec.CIDR, spec.LocalIP, spec.ServerIP, spec.MTU}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp("", "portway-vnet-manifest-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(data)
	}
	closeError := temporary.Close()
	if err != nil {
		return err
	}
	if closeError != nil {
		return closeError
	}
	if err := privilegedCommand("mkdir", "-p", filepath.Dir(manifestPath())).Run(); err != nil {
		return err
	}
	if err := privilegedCommand("install", "-o", "root", "-g", platformRootGroup(), "-m", "0644", name, manifestPath()).Run(); err != nil {
		return fmt.Errorf("install VNet ownership manifest: %w", err)
	}
	return nil
}

func readManifest() (ownershipManifest, error) {
	info, err := os.Lstat(manifestPath())
	if err != nil {
		return ownershipManifest{}, err
	}
	if !safeManifestFile(info) {
		return ownershipManifest{}, fmt.Errorf("%w: unsafe ownership manifest permissions", ErrStateMismatch)
	}
	data, err := os.ReadFile(manifestPath())
	if err != nil {
		return ownershipManifest{}, err
	}
	var manifest ownershipManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return ownershipManifest{}, fmt.Errorf("%w: invalid ownership manifest", ErrStateMismatch)
	}
	if manifest.SchemaVersion != manifestSchema || manifest.LogicalName != LogicalInterfaceName ||
		manifest.PlatformInterface == "" || (manifest.Role != NetworkRoleClient && manifest.Role != NetworkRoleServer) {
		return ownershipManifest{}, fmt.Errorf("%w: invalid ownership manifest identity", ErrStateMismatch)
	}
	identifier, identifierError := hex.DecodeString(manifest.InstallationID)
	if identifierError != nil || len(identifier) != 16 || validateNetworkSpec(NetworkSpec{
		Role: manifest.Role, CIDR: manifest.CIDR, LocalIP: manifest.LocalIP,
		ServerIP: manifest.ServerIP, MTU: manifest.MTU,
	}) != nil {
		return ownershipManifest{}, fmt.Errorf("%w: invalid ownership manifest contents", ErrStateMismatch)
	}
	return manifest, nil
}

func interfaceMatchesManifest(manifest ownershipManifest) bool {
	interfaceValue, err := net.InterfaceByName(manifest.PlatformInterface)
	if err != nil || interfaceValue.MTU != int(manifest.MTU) {
		return false
	}
	prefix, err := netip.ParsePrefix(manifest.CIDR)
	if err != nil {
		return false
	}
	addresses, err := interfaceValue.Addrs()
	if err != nil {
		return false
	}
	expected := manifest.LocalIP + "/" + fmt.Sprint(prefix.Bits())
	for _, address := range addresses {
		if address.String() == expected {
			return true
		}
	}
	return false
}

func validateNetworkSpec(spec NetworkSpec) error {
	prefix, err := netip.ParsePrefix(spec.CIDR)
	local, localError := netip.ParseAddr(spec.LocalIP)
	server, serverError := netip.ParseAddr(spec.ServerIP)
	if err != nil || localError != nil || serverError != nil || !prefix.Contains(local) ||
		!prefix.Contains(server) || spec.MTU < 576 || (spec.Role != NetworkRoleClient && spec.Role != NetworkRoleServer) {
		return errors.New("invalid VNet system network specification")
	}
	return nil
}

func privilegedCommand(name string, arguments ...string) *exec.Cmd {
	var command *exec.Cmd
	if os.Geteuid() == 0 {
		command = exec.Command(name, arguments...)
	} else {
		command = exec.Command("sudo", append([]string{name}, arguments...)...)
	}
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command
}

func manifestPath() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/Portway/vnetwork/portway0.json"
	}
	return "/var/lib/portway/vnetwork/portway0.json"
}
