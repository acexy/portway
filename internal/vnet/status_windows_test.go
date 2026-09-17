//go:build windows && amd64

package vnet

import (
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

type testNetworkAddress string

func (address testNetworkAddress) Network() string { return "test" }
func (address testNetworkAddress) String() string  { return string(address) }

func TestWindowsStatusIPv4(t *testing.T) {
	cidr, localIP, err := windowsStatusIPv4([]net.Addr{
		testNetworkAddress("fe80::1/64"),
		testNetworkAddress("172.20.0.2/16"),
	})
	if err != nil || cidr != "172.20.0.0/16" || localIP != "172.20.0.2" {
		t.Fatalf("windowsStatusIPv4() = (%q, %q, %v)", cidr, localIP, err)
	}
}

func TestValidateWindowsAdapterGUIDRejectsForeignAdapter(t *testing.T) {
	if err := validateWindowsAdapterGUID(windows.GUID{}); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("error = %v, want ErrForeignResource", err)
	}
	if err := validateWindowsAdapterGUID(windowsAdapterGUID); err != nil {
		t.Fatalf("Portway adapter GUID rejected: %v", err)
	}
}

func TestWindowsStatusIPv4RejectsMultipleAddresses(t *testing.T) {
	_, _, err := windowsStatusIPv4([]net.Addr{
		testNetworkAddress("172.20.0.2/16"),
		testNetworkAddress("172.20.0.3/16"),
	})
	if !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("error = %v, want ErrStateMismatch", err)
	}
}
