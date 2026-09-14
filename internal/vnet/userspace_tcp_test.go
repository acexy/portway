package vnet

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestUserspaceTCPForwardsRemoteFlowToLoopback(t *testing.T) {
	backend, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	backendResult := make(chan error, 1)
	go func() {
		connection, acceptError := backend.AcceptTCP()
		if acceptError != nil {
			backendResult <- acceptError
			return
		}
		defer connection.Close()
		_, acceptError = io.Copy(connection, connection)
		backendResult <- acceptError
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peerStack, peerLink := newUserspaceTCPTestPeer(t, [4]byte{172, 20, 0, 2})
	defer func() {
		peerLink.Close()
		peerStack.Close()
		peerStack.Wait()
	}()
	var runtime *UserspaceTCP
	runtime, err = NewUserspaceTCP(
		ctx, netip.MustParseAddr("172.20.0.3"), 16, 1280,
		func(packet []byte) error {
			injectUserspaceTCPTestPacket(peerLink, packet)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	go func() {
		for {
			packet := peerLink.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			data := append([]byte(nil), view.AsSlice()...)
			view.Release()
			packet.DecRef()
			runtime.Handle(data)
		}
	}()

	dialContext, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	defer dialCancel()
	serverAddress := tcpip.AddrFrom4([4]byte{172, 20, 0, 3})
	remote, err := gonet.DialContextTCP(dialContext, peerStack, tcpip.FullAddress{
		NIC: userspaceTCPNICID, Addr: serverAddress,
		Port: uint16(backend.Addr().(*net.TCPAddr).Port),
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Write([]byte("vnet")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(remote, response); err != nil {
		t.Fatal(err)
	}
	_ = remote.Close()
	if string(response) != "vnet" {
		t.Fatalf("unexpected userspace TCP response %q", response)
	}
	cancel()
	select {
	case err := <-backendResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("loopback backend did not close")
	}
}

func TestUserspaceTCPRejectsRemoteFlowWhenLoopbackPortIsClosed(t *testing.T) {
	closedPort := reserveClosedTCPPort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peerStack, peerLink := newUserspaceTCPTestPeer(t, [4]byte{172, 20, 0, 2})
	defer func() {
		peerLink.Close()
		peerStack.Close()
		peerStack.Wait()
	}()
	var runtime *UserspaceTCP
	runtime, err := NewUserspaceTCP(
		ctx, netip.MustParseAddr("172.20.0.3"), 16, 1280,
		func(packet []byte) error {
			injectUserspaceTCPTestPacket(peerLink, packet)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	go func() {
		for {
			packet := peerLink.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			data := append([]byte(nil), view.AsSlice()...)
			view.Release()
			packet.DecRef()
			runtime.Handle(data)
		}
	}()

	dialContext, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	defer dialCancel()
	startedAt := time.Now()
	remote, err := gonet.DialContextTCP(dialContext, peerStack, tcpip.FullAddress{
		NIC: userspaceTCPNICID, Addr: tcpip.AddrFrom4([4]byte{172, 20, 0, 3}),
		Port: closedPort,
	}, ipv4.ProtocolNumber)
	if remote != nil {
		_ = remote.Close()
	}
	if err == nil {
		t.Fatal("expected closed loopback port to reject TCP connection")
	}
	if elapsed := time.Since(startedAt); elapsed >= time.Second {
		t.Fatalf("closed loopback port rejection took %s", elapsed)
	}
}

func reserveClosedTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestUserspaceTCPForwardsRemoteUDPFlowToLoopback(t *testing.T) {
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	backendResult := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64)
		count, address, readError := backend.ReadFromUDP(buffer)
		if readError == nil {
			_, readError = backend.WriteToUDP(buffer[:count], address)
		}
		backendResult <- readError
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peerStack, peerLink := newUserspaceTCPTestPeer(t, [4]byte{172, 20, 0, 2})
	defer func() {
		peerLink.Close()
		peerStack.Close()
		peerStack.Wait()
	}()
	var runtime *UserspaceTCP
	runtime, err = NewUserspaceTCP(
		ctx, netip.MustParseAddr("172.20.0.3"), 16, 1280,
		func(packet []byte) error {
			injectUserspaceTCPTestPacket(peerLink, packet)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	go func() {
		for {
			packet := peerLink.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			data := append([]byte(nil), view.AsSlice()...)
			view.Release()
			packet.DecRef()
			runtime.Handle(data)
		}
	}()

	serverAddress := tcpip.AddrFrom4([4]byte{172, 20, 0, 3})
	remote, err := gonet.DialUDP(peerStack, nil, &tcpip.FullAddress{
		NIC: userspaceTCPNICID, Addr: serverAddress,
		Port: uint16(backend.LocalAddr().(*net.UDPAddr).Port),
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	if err := remote.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Write([]byte("datagram")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 64)
	count, err := remote.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	if string(response[:count]) != "datagram" {
		t.Fatalf("unexpected userspace UDP response %q", response[:count])
	}
	select {
	case err := <-backendResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("loopback UDP backend did not receive datagram")
	}
}

func newUserspaceTCPTestPeer(t *testing.T, address [4]byte) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	networkStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	linkEndpoint := channel.New(userspaceTCPPacketQueue, 1280, "")
	if err := networkStack.CreateNIC(userspaceTCPNICID, linkEndpoint); err != nil {
		t.Fatalf("create peer NIC: %s", err)
	}
	if err := networkStack.AddProtocolAddress(userspaceTCPNICID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address: tcpip.AddrFrom4(address), PrefixLen: 16,
		},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("assign peer address: %s", err)
	}
	networkStack.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet, NIC: userspaceTCPNICID,
	}})
	return networkStack, linkEndpoint
}

func injectUserspaceTCPTestPacket(endpoint *channel.Endpoint, packet []byte) {
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	endpoint.InjectInbound(ipv4.ProtocolNumber, packetBuffer)
	packetBuffer.DecRef()
}
