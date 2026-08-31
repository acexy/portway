package client

import (
	"context"
	"net"
	"testing"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
)

func TestForwardManagerKeepsDormantConfigurationAndRestoresListener(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().(*net.TCPAddr)
	probe.Close()

	configuration := config.ForwardConfig{
		Name: "database", Type: protocol.ForwardTypeTCP,
		Listen: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(address.Port)},
		Target: config.EndpointConfig{IP: "127.0.0.1", Port: 5432},
	}
	manager, err := newForwardManager(
		context.Background(), logging.New("test"), "client", "session", nil, nil,
		[]config.ForwardConfig{configuration},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.close()
	if err := manager.applyBindings([]protocol.ForwardResult{{
		Name: configuration.Name, Type: configuration.Type, BindingID: "binding", Active: false,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := manager.start(); err != nil {
		t.Fatal(err)
	}
	assertTCPAddressAvailable(t, address.String())

	if err := manager.activate(protocol.ForwardBindingActivated{
		Name: configuration.Name, Type: configuration.Type, BindingID: "binding", Generation: 2,
	}); err != nil {
		t.Fatal(err)
	}
	assertTCPAddressUnavailable(t, address.String())

	manager.revoke(protocol.ForwardBindingRevoked{
		Name: configuration.Name, Type: configuration.Type, BindingID: "binding", Generation: 3,
	})
	assertTCPAddressAvailable(t, address.String())
}

func TestForwardManagerRejectsMissingUDPServerLimits(t *testing.T) {
	configuration := config.ForwardConfig{
		Name: "dns", Type: protocol.ForwardTypeUDP,
		Listen: config.EndpointConfig{IP: "127.0.0.1", Port: 1053},
		Target: config.EndpointConfig{IP: "127.0.0.1", Port: 53},
	}
	manager, err := newForwardManager(
		context.Background(), logging.New("test"), "client", "session", nil, nil,
		[]config.ForwardConfig{configuration},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.close()
	if err := manager.applyBindings([]protocol.ForwardResult{{
		Name: configuration.Name, Type: configuration.Type, BindingID: "binding", Active: true,
	}}); err == nil {
		t.Fatal("UDP Forward binding without server limits was accepted")
	}
}

func assertTCPAddressAvailable(t *testing.T, address string) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("address %s is unavailable: %v", address, err)
	}
	listener.Close()
}

func assertTCPAddressUnavailable(t *testing.T, address string) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err == nil {
		listener.Close()
		t.Fatalf("address %s remained available", address)
	}
}
