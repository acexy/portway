//go:build windows && amd64

package system

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	packetdata "github.com/acexy/portway/internal/vnet/packet"
)

func TestParseWindowsNetworkRoutes(t *testing.T) {
	data := []byte(`
          0.0.0.0          0.0.0.0       192.0.2.1      192.0.2.10     25
       172.20.0.0      255.255.0.0         On-link       172.20.0.1    281
       192.0.2.10  255.255.255.255         On-link       192.0.2.10    281
`)
	routes, err := parseWindowsNetworkRoutes(data)
	if err != nil {
		t.Fatalf("parse Windows routes: %v", err)
	}
	if len(routes) != 3 || routes[1].String() != "172.20.0.0/16" || routes[2].Bits() != 32 {
		t.Fatalf("routes = %v", routes)
	}
}

func TestParseWindowsNetworkRoutesRejectsNonContiguousMask(t *testing.T) {
	data := []byte("172.20.0.0 255.0.255.0 On-link 172.20.0.1 1")
	if _, err := parseWindowsNetworkRoutes(data); err == nil {
		t.Fatal("non-contiguous Windows route mask was accepted")
	}
}

func TestWindowsVNetLive(t *testing.T) {
	if os.Getenv("PORTWAY_TEST_WINDOWS_VNET") != "1" {
		t.Skip("set PORTWAY_TEST_WINDOWS_VNET=1 to run the privileged Wintun test")
	}
	if !windowsProcessElevated() {
		t.Fatal("live Windows VNet test requires an administrator process")
	}
	_, sourceFile, _, _ := runtime.Caller(0)
	dllPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "assets", "wintun", "bin", "amd64", "wintun.dll")
	dllPath, err := filepath.Abs(dllPath)
	if err != nil {
		t.Fatalf("resolve Wintun path: %v", err)
	}
	routes, err := windowsNetworkRoutes(context.Background())
	if err != nil {
		t.Fatalf("inspect Windows routes: %v", err)
	}
	var spec NetworkSpec
	for _, cidr := range []string{"10.253.253.0/30", "172.31.253.0/30", "192.168.253.0/30"} {
		prefix := netip.MustParsePrefix(cidr)
		candidate := NetworkSpec{
			Role: NetworkRoleServer, CIDR: cidr, LocalIP: prefix.Addr().Next().String(),
			ServerIP: prefix.Addr().Next().String(), MTU: 1280, OwnerUID: -1,
		}
		if checkNetworkConflicts(candidate, routes) == nil {
			spec = candidate
			break
		}
	}
	if spec.CIDR == "" {
		t.Skip("no isolated private test prefix is available")
	}
	device, err := prepareWindowsNetwork(context.Background(), spec, dllPath)
	if err != nil {
		t.Fatalf("prepare Windows VNet: %v", err)
	}
	if device.Name() != LogicalInterfaceName || validateWindowsNetworkConfiguration(context.Background(), spec) != nil {
		_ = device.Close()
		t.Fatal("Windows VNet configuration is not active")
	}
	prefix := netip.MustParsePrefix(spec.CIDR)
	remoteIP := prefix.Addr().Next().Next()
	connection, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(spec.LocalIP)}, &net.UDPAddr{IP: remoteIP.AsSlice(), Port: 32000})
	if err != nil {
		_ = device.Close()
		t.Fatalf("dial through Windows VNet: %v", err)
	}
	defer connection.Close()
	packetResult := make(chan []byte, 1)
	readError := make(chan error, 1)
	packetDiagnostics := make(chan string, 8)
	go func() {
		for {
			packet := make([]byte, spec.MTU)
			length, readErr := device.ReadPacket(packet)
			if readErr != nil {
				readError <- readErr
				return
			}
			flow, parseError := packetdata.ParseIPv4(packet[:length])
			select {
			case packetDiagnostics <- fmt.Sprintf("length=%d flow=%+v error=%v", length, flow, parseError):
			default:
			}
			if parseError == nil && flow.SourceIP.String() == spec.LocalIP && flow.DestinationIP == remoteIP {
				packetResult <- packet[:length]
				return
			}
		}
	}()
	if _, err := connection.Write([]byte("portway-vnet")); err != nil {
		_ = device.Close()
		t.Fatalf("write through Windows VNet: %v", err)
	}
	select {
	case packet := <-packetResult:
		flow, parseError := packetdata.ParseIPv4(packet)
		if parseError != nil || flow.Protocol != packetdata.ProtocolUDP {
			_ = device.Close()
			t.Fatalf("unexpected Windows VNet packet: flow=%+v error=%v", flow, parseError)
		}
	case err := <-readError:
		_ = device.Close()
		t.Fatalf("read Windows VNet packet: %v", err)
	case <-time.After(3 * time.Second):
		_ = device.Close()
		close(packetDiagnostics)
		var diagnostics []string
		for diagnostic := range packetDiagnostics {
			diagnostics = append(diagnostics, diagnostic)
		}
		t.Fatalf("timed out waiting for a Windows VNet packet; observed=%v", diagnostics)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("close Windows VNet: %v", err)
	}
	if _, err := net.InterfaceByName(LogicalInterfaceName); err == nil {
		t.Fatal("temporary Windows VNet adapter remained after close")
	}
}

func TestWindowsNetworkLockCrossThreadCleanup(t *testing.T) {
	// Pin the creator so cleanup is guaranteed to execute on another OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name := fmt.Sprintf("Local\\Portway-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	handle, inUse, err := acquireNamedWindowsNetworkLock(name)
	if err != nil || inUse {
		t.Fatalf("create lock: inUse=%t error=%v", inUse, err)
	}
	defer func() {
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
	}()
	if err := windows.ReleaseMutex(handle); !errors.Is(err, windows.ERROR_NOT_OWNER) {
		t.Fatalf("existence lease unexpectedly acquired thread ownership: %v", err)
	}
	other, inUse, err := acquireNamedWindowsNetworkLock(name)
	if other != 0 {
		_ = windows.CloseHandle(other)
	}
	if err != nil || !inUse {
		t.Fatalf("duplicate lock: inUse=%t error=%v", inUse, err)
	}
	closed := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		closed <- windows.CloseHandle(handle)
	}()
	if err := <-closed; err != nil {
		t.Fatalf("cross-thread cleanup: %v", err)
	}
	handle = 0
	replacement, inUse, err := acquireNamedWindowsNetworkLock(name)
	if replacement != 0 {
		defer windows.CloseHandle(replacement)
	}
	if err != nil || inUse {
		t.Fatalf("reacquire after cleanup: inUse=%t error=%v", inUse, err)
	}
}

func TestWindowsNetworkLockRecognizesLegacyOwner(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name := fmt.Sprintf("Local\\Portway-legacy-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := windows.CreateMutex(nil, true, pointer)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(legacy)
	defer windows.ReleaseMutex(legacy)
	handle, inUse, err := acquireNamedWindowsNetworkLock(name)
	if handle != 0 {
		defer windows.CloseHandle(handle)
	}
	if err != nil || !inUse {
		t.Fatalf("legacy lock ignored: inUse=%t error=%v", inUse, err)
	}
}
