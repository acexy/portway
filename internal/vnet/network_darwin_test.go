//go:build darwin

package vnet

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestDarwinAuthorizationNoticeWithoutTerminalColor(t *testing.T) {
	var output bytes.Buffer
	writeDarwinAuthorizationNotice(&output, "VNet ready", "32")
	if output.String() != "VNet ready\n" {
		t.Fatalf("unexpected authorization notice: %q", output.String())
	}
}

func TestDarwinRouteSnapshotIncludesDefaultAndHostRoutes(t *testing.T) {
	defaultRoute := &route.RouteMessage{Addrs: make([]route.Addr, syscall.RTAX_MAX)}
	defaultRoute.Addrs[syscall.RTAX_DST] = &route.Inet4Addr{}
	defaultRoute.Addrs[syscall.RTAX_NETMASK] = &route.Inet4Addr{}
	hostRoute := &route.RouteMessage{Flags: syscall.RTF_HOST, Addrs: make([]route.Addr, syscall.RTAX_MAX)}
	hostRoute.Addrs[syscall.RTAX_DST] = &route.Inet4Addr{IP: [4]byte{172, 20, 1, 2}}
	prefixes, err := parseDarwinNetworkRoutes([]route.Message{defaultRoute, hostRoute})
	if err != nil || len(prefixes) != 2 || prefixes[0].Bits() != 0 || prefixes[1].Bits() != 32 {
		t.Fatalf("route prefixes = %v, error = %v", prefixes, err)
	}
	defaultRoute.Addrs[syscall.RTAX_NETMASK] = nil
	if _, err := parseDarwinNetworkRoutes([]route.Message{defaultRoute}); err == nil {
		t.Fatal("missing route mask was accepted")
	}
}

func TestDarwinManualNetworkManagementIsUnavailable(t *testing.T) {
	if ManualNetworkManagementSupported() {
		t.Fatal("macOS must manage its process-owned utun during run")
	}
}

func TestDarwinHelperRejectsInvalidInvocation(t *testing.T) {
	handled, err := RunPlatformHelper([]string{darwinHelperCommand})
	if !handled || err == nil {
		t.Fatal("expected hidden helper command with missing arguments to be rejected")
	}
}

func TestValidateDarwinHelperSocket(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "portway-vnetwork-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "helper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateDarwinHelperSocket(path, os.Getuid()); err != nil {
		t.Fatalf("validate helper socket: %v", err)
	}
}

func TestDarwinHelperPreservesNetworkConflict(t *testing.T) {
	response := darwinHelperResponse{Error: "route conflict", ForeignResource: true}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var decoded darwinHelperResponse
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(decoded.networkError(), ErrForeignResource) {
		t.Fatalf("lost conflict category: %v", decoded.networkError())
	}
	response.ForeignResource = false
	if errors.Is(response.networkError(), ErrForeignResource) {
		t.Fatal("ordinary helper failure classified as conflict")
	}
}

func TestDarwinManagedDeviceWaitsAfterClose(t *testing.T) {
	descriptors, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(descriptors[1])
	device, err := newDarwinDevice(descriptors[0], "test-utun")
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	checks := 0
	managed := &darwinManagedDevice{Device: device, removed: func() (bool, error) {
		checks++
		if _, err := device.WritePacket([]byte{1}); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("checked removal before closing FD: %v", err)
		}
		return checks == 2, nil
	}}
	if err := managed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := managed.Close(); err != nil || checks != 2 {
		t.Fatalf("close not idempotent: checks=%d err=%v", checks, err)
	}
}
