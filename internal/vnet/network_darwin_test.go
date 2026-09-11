//go:build darwin

package vnet

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

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
