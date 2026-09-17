//go:build windows && amd64

package vnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
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
	dllPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "assets", "wintun", "bin", "amd64", "wintun.dll")
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
			flow, parseError := ParseIPv4(packet[:length])
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
		flow, parseError := ParseIPv4(packet)
		if parseError != nil || flow.Protocol != protocolUDP {
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
