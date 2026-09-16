//go:build darwin

package vnet

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const darwinHelperCommand = "__vnetwork_darwin_helper"

type darwinHelperResponse struct {
	Nonce         string `json:"nonce"`
	InterfaceName string `json:"interface_name,omitempty"`
	Error         string `json:"error,omitempty"`
}

type darwinHelperAccept struct {
	connection *net.UnixConn
	err        error
}

func preparePlatformNetwork(ctx context.Context, spec NetworkSpec) (Device, error) {
	if os.Geteuid() == 0 {
		return configureDarwinDevice(ctx, spec)
	}
	return requestDarwinHelper(ctx, spec)
}

func configureDarwinDevice(ctx context.Context, spec NetworkSpec) (Device, error) {
	if err := cleanupDarwinLegacyManifest(); err != nil {
		return nil, err
	}
	routes, err := darwinNetworkRoutes()
	if err != nil {
		return nil, err
	}
	if err := checkNetworkConflicts(spec, routes); err != nil {
		return nil, err
	}
	device, err := OpenDevice()
	if err != nil {
		return nil, err
	}
	prefixLength, _ := netipPrefixLength(spec.CIDR)
	if err := exec.CommandContext(ctx, "/sbin/ifconfig", device.Name(), "inet", spec.LocalIP, spec.ServerIP,
		"netmask", cidrNetmask(prefixLength), "mtu", strconv.Itoa(int(spec.MTU)), "up").Run(); err != nil {
		device.Close()
		return nil, fmt.Errorf("configure macOS VNet interface: %w", err)
	}
	if err := exec.CommandContext(ctx, "/sbin/route", "-n", "add", "-net", spec.CIDR, "-interface", device.Name()).Run(); err != nil {
		device.Close()
		return nil, fmt.Errorf("configure macOS VNet route: %w", err)
	}
	return device, nil
}

func requestDarwinHelper(ctx context.Context, spec NetworkSpec) (Device, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	directory, err := os.MkdirTemp("/tmp", "portway-vnetwork-*")
	if err != nil {
		return nil, fmt.Errorf("create macOS VNet helper directory: %w", err)
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, err
	}
	socketPath := filepath.Join(directory, "helper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen for macOS VNet helper: %w", err)
	}
	defer listener.Close()
	stopListener := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopListener()
	if err := os.Chmod(socketPath, 0600); err != nil {
		return nil, err
	}
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(nonceBytes)
	encodedSpec, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	authorizationCached := exec.CommandContext(ctx, "sudo", "-n", "true").Run() == nil
	if !authorizationCached && !interactiveTerminalAvailable() {
		return nil, errors.New("macOS VNet requires an interactive administrator authorization")
	}
	if !authorizationCached {
		authorizationNotice := fmt.Sprintf(
			"Portway VNet is enabled and requires administrator permission to create the temporary macOS network %s (IP %s, CIDR %s).",
			LogicalInterfaceName, spec.LocalIP, spec.CIDR,
		)
		writeDarwinAuthorizationNotice(os.Stderr, authorizationNotice, "31")
	}
	command := exec.CommandContext(ctx, "sudo", executable, darwinHelperCommand, socketPath,
		base64.RawURLEncoding.EncodeToString(encodedSpec), nonce)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start macOS VNet helper: %w", err)
	}
	_ = listener.SetDeadline(time.Now().Add(2 * time.Minute))
	accepts := make(chan darwinHelperAccept, 1)
	waits := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		accepts <- darwinHelperAccept{connection: connection, err: err}
	}()
	go func() { waits <- command.Wait() }()
	var accepted darwinHelperAccept
	var waitError error
	helperExited := false
	select {
	case accepted = <-accepts:
	case waitError = <-waits:
		helperExited = true
		select {
		case accepted = <-accepts:
		case <-time.After(200 * time.Millisecond):
			if waitError == nil {
				waitError = errors.New("helper exited without returning a device")
			}
			return nil, fmt.Errorf("macOS VNet helper exited before connecting: %w", waitError)
		}
	}
	if accepted.err != nil {
		_ = command.Process.Kill()
		if !helperExited {
			waitError = <-waits
		}
		return nil, fmt.Errorf("accept macOS VNet helper: %w", accepted.err)
	}
	connection := accepted.connection
	stopConnection := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopConnection()
	device, receiveError := receiveDarwinDevice(connection, nonce)
	_ = connection.Close()
	if !helperExited {
		waitError = <-waits
	}
	if receiveError != nil {
		return nil, receiveError
	}
	if waitError != nil {
		device.Close()
		return nil, fmt.Errorf("macOS VNet helper exited: %w", waitError)
	}
	if !authorizationCached {
		completionNotice := fmt.Sprintf(
			"Portway VNet network %s is ready (interface %s, IP %s, CIDR %s).",
			LogicalInterfaceName, device.Name(), spec.LocalIP, spec.CIDR,
		)
		writeDarwinAuthorizationNotice(os.Stderr, completionNotice, "32")
	}
	return device, nil
}

func writeDarwinAuthorizationNotice(writer io.Writer, message string, color string) {
	useColor := false
	if file, ok := writer.(*os.File); ok {
		if info, err := file.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			useColor = true
		}
	}
	if useColor {
		_, _ = fmt.Fprintf(writer, "\x1b[%sm%s\x1b[0m\n", color, message)
		return
	}
	_, _ = fmt.Fprintln(writer, message)
}

func cleanupDarwinLegacyManifest() error {
	manifest, err := readManifest()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := net.InterfaceByName(manifest.PlatformInterface); err == nil {
		return fmt.Errorf("%w: recorded macOS utun is still active", ErrForeignResource)
	}
	if err := os.Remove(manifestPath()); err != nil {
		return fmt.Errorf("remove legacy macOS VNet ownership manifest: %w", err)
	}
	return nil
}

func receiveDarwinDevice(connection *net.UnixConn, nonce string) (Device, error) {
	file, err := connection.File()
	if err != nil {
		return nil, err
	}
	credentials, credentialError := unix.GetsockoptXucred(int(file.Fd()), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	_ = file.Close()
	if credentialError != nil || credentials.Uid != 0 {
		return nil, errors.New("macOS VNet helper peer is not root")
	}
	data := make([]byte, 4096)
	control := make([]byte, unix.CmsgSpace(4))
	dataLength, controlLength, _, _, err := connection.ReadMsgUnix(data, control)
	if err != nil {
		return nil, fmt.Errorf("receive macOS VNet helper response: %w", err)
	}
	var response darwinHelperResponse
	if err := json.Unmarshal(data[:dataLength], &response); err != nil || response.Nonce != nonce {
		return nil, errors.New("invalid macOS VNet helper response")
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}
	messages, err := unix.ParseSocketControlMessage(control[:controlLength])
	if err != nil || len(messages) != 1 {
		return nil, errors.New("macOS VNet helper did not return one device descriptor")
	}
	descriptors, err := unix.ParseUnixRights(&messages[0])
	if err != nil || len(descriptors) != 1 || response.InterfaceName == "" {
		for _, descriptor := range descriptors {
			_ = unix.Close(descriptor)
		}
		return nil, errors.New("invalid macOS VNet device descriptor")
	}
	if len(response.InterfaceName) < 5 || response.InterfaceName[:4] != "utun" {
		_ = unix.Close(descriptors[0])
		return nil, errors.New("invalid macOS VNet interface name")
	}
	unix.CloseOnExec(descriptors[0])
	return newDarwinDevice(descriptors[0], response.InterfaceName)
}

func runPlatformHelper(arguments []string) (bool, error) {
	if len(arguments) == 0 || arguments[0] != darwinHelperCommand {
		return false, nil
	}
	if len(arguments) != 4 || os.Geteuid() != 0 {
		return true, errors.New("invalid macOS VNet helper invocation")
	}
	socketPath, encodedSpec, nonce := arguments[1], arguments[2], arguments[3]
	data, err := base64.RawURLEncoding.DecodeString(encodedSpec)
	if err != nil {
		return true, errors.New("invalid macOS VNet helper request")
	}
	var spec NetworkSpec
	if err := json.Unmarshal(data, &spec); err != nil || validateNetworkSpec(spec) != nil ||
		spec.OwnerUID <= 0 || len(nonce) != 64 {
		return true, errors.New("invalid macOS VNet helper request")
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return true, errors.New("invalid macOS VNet helper nonce")
	}
	if err := validateDarwinHelperSocket(socketPath, spec.OwnerUID); err != nil {
		return true, err
	}
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return true, fmt.Errorf("connect macOS VNet helper socket: %w", err)
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	go func() {
		var probe [1]byte
		_, _ = connection.Read(probe[:])
		cancel()
	}()
	device, configureError := configureDarwinDevice(ctx, spec)
	response := darwinHelperResponse{Nonce: nonce}
	var rights []byte
	if configureError != nil {
		response.Error = configureError.Error()
	} else {
		response.InterfaceName = device.Name()
		rights = unix.UnixRights(device.(*darwinDevice).fileDescriptor)
	}
	responseData, _ := json.Marshal(response)
	_, _, writeError := connection.WriteMsgUnix(responseData, rights, nil)
	if device != nil {
		_ = device.Close()
	}
	if writeError != nil {
		return true, fmt.Errorf("send macOS VNet helper response: %w", writeError)
	}
	return true, configureError
}

func validateDarwinHelperSocket(socketPath string, ownerUID int) error {
	directory := filepath.Dir(socketPath)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("unsafe macOS VNet helper directory")
	}
	stat, valid := info.Sys().(*syscall.Stat_t)
	if !valid || int(stat.Uid) != ownerUID {
		return errors.New("invalid macOS VNet helper directory owner")
	}
	socketInfo, err := os.Lstat(socketPath)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != 0600 {
		return errors.New("unsafe macOS VNet helper socket")
	}
	return nil
}

func uninstallPlatformNetwork(ownershipManifest) error {
	return errors.New("manual VNet management is unavailable on macOS")
}

func repairPlatformNetwork(spec NetworkSpec) (Device, error) {
	return preparePlatformNetwork(context.Background(), spec)
}
func platformRootGroup() string              { return "wheel" }
func manualNetworkManagementSupported() bool { return false }
func networkUninstallSupported() bool         { return false }
func runtimeHelperSupported() bool           { return true }
func platformSupported() bool                { return true }
func runtimeReprepareSupported() bool        { return false }

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

func platformIdentityMatches(ownershipManifest) bool { return false }

func uninstallEphemeralNetwork() (string, bool, error) { return "", false, nil }

func darwinNetworkRoutes() ([]netip.Prefix, error) {
	data, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("inspect macOS VNet routes: %w", err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, data)
	if err != nil {
		return nil, err
	}
	return parseDarwinNetworkRoutes(messages)
}

func parseDarwinNetworkRoutes(messages []route.Message) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, message := range messages {
		entry, ok := message.(*route.RouteMessage)
		if !ok || len(entry.Addrs) <= syscall.RTAX_DST {
			continue
		}
		destination, ok := entry.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		if !ok {
			continue
		}
		bits := 32
		if entry.Flags&syscall.RTF_HOST == 0 {
			if len(entry.Addrs) <= syscall.RTAX_NETMASK {
				return nil, errors.New("macOS IPv4 route has no netmask")
			}
			mask, ok := entry.Addrs[syscall.RTAX_NETMASK].(*route.Inet4Addr)
			if !ok {
				return nil, errors.New("invalid macOS IPv4 route netmask")
			}
			var width int
			bits, width = net.IPMask(mask.IP[:]).Size()
			if width != 32 {
				return nil, errors.New("non-contiguous macOS IPv4 route netmask")
			}
		}
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(destination.IP), bits))
	}
	return prefixes, nil
}
