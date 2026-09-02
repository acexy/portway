package server

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/client"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
)

func TestTCPForwardEndToEnd(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetContext, cancelTarget := context.WithCancel(context.Background())
	defer cancelTarget()
	go runEchoServer(targetContext, target)

	serverAddress := reserveTCPAddress(t)
	listenAddress := reserveTCPAddress(t)
	token := "test-token-with-at-least-32-random-bytes"
	serverConfiguration := config.DefaultServer()
	serverConfiguration.Transport.ListenAddress = serverAddress.String()
	serverConfiguration.Authentication.SharedToken = &token
	serverConfiguration.Forwards = loopbackForwardPolicy()
	clientConfiguration := config.DefaultClient()
	clientConfiguration.Authentication.ClientID = "tcp-forward-client"
	clientConfiguration.Transport.ServerAddress = serverAddress.String()
	clientConfiguration.Authentication.Token = token
	clientConfiguration.Forwards = []config.ForwardConfig{{
		Name: "server-echo", Type: protocol.ForwardTypeTCP,
		Listen: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(listenAddress.Port)},
		Target: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)},
	}}

	cancelServer, serverErrors, cancelClient, clientErrors := runForwardServices(
		t, serverConfiguration, clientConfiguration,
	)
	visitor := dialWithRetry(t, listenAddress.String(), 10*time.Second)
	message := []byte("portway TCP Forward")
	if _, err := visitor.Write(message); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(message))
	if _, err := io.ReadFull(visitor, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != string(message) {
		t.Fatalf("unexpected TCP Forward response %q", response)
	}
	visitor.Close()
	stopForwardServices(t, cancelClient, clientErrors, cancelServer, serverErrors)
}

func TestUDPForwardEndToEnd(t *testing.T) {
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetContext, cancelTarget := context.WithCancel(context.Background())
	defer cancelTarget()
	go runUDPEchoServer(targetContext, target)

	serverAddress := reserveTCPAddress(t)
	listenAddress := reserveUDPAddress(t)
	token := "test-token-with-at-least-32-random-bytes"
	serverConfiguration := config.DefaultServer()
	serverConfiguration.Transport.ListenAddress = serverAddress.String()
	serverConfiguration.Authentication.SharedToken = &token
	serverConfiguration.Forwards = loopbackForwardPolicy()
	clientConfiguration := config.DefaultClient()
	clientConfiguration.Authentication.ClientID = "udp-forward-client"
	clientConfiguration.Transport.ServerAddress = serverAddress.String()
	clientConfiguration.Authentication.Token = token
	clientConfiguration.Forwards = []config.ForwardConfig{{
		Name: "server-dns", Type: protocol.ForwardTypeUDP,
		Listen: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(listenAddress.Port)},
		Target: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port)},
	}}

	cancelServer, serverErrors, cancelClient, clientErrors := runForwardServices(
		t, serverConfiguration, clientConfiguration,
	)
	visitor, err := net.DialUDP("udp", nil, listenAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer visitor.Close()
	message := []byte("portway UDP Forward")
	response := make([]byte, 128)
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, _ = visitor.Write(message)
		_ = visitor.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		length, err := visitor.Read(response)
		if err == nil {
			if string(response[:length]) != string(message) {
				t.Fatalf("unexpected UDP Forward response %q", response[:length])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP Forward did not become ready: %v", err)
		}
	}
	stopForwardServices(t, cancelClient, clientErrors, cancelServer, serverErrors)
}

func TestTCPForwardGovernedEndToEnd(t *testing.T) {
	runRestrictedTCPForwardEndToEnd(t, protocol.ManagementModeGoverned)
}

func TestTCPForwardManagedEndToEnd(t *testing.T) {
	runRestrictedTCPForwardEndToEnd(t, protocol.ManagementModeManaged)
}

func runRestrictedTCPForwardEndToEnd(t *testing.T, mode protocol.ManagementMode) {
	t.Helper()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetContext, cancelTarget := context.WithCancel(context.Background())
	defer cancelTarget()
	go runEchoServer(targetContext, target)
	serverAddress := reserveTCPAddress(t)
	listenAddress := reserveTCPAddress(t)
	token := "restricted-forward-token-with-at-least-32-bytes"
	forward := config.ForwardConfig{
		Name: "restricted-echo", Type: protocol.ForwardTypeTCP,
		Listen: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(listenAddress.Port)},
		Target: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)},
	}
	serverConfiguration := config.DefaultServer()
	serverConfiguration.Transport.ListenAddress = serverAddress.String()
	serverConfiguration.Authentication.SharedToken = nil
	serverConfiguration.Forwards = loopbackForwardPolicy()
	clientConfiguration := config.DefaultClient()
	clientConfiguration.Authentication.ClientID = "restricted-forward-client"
	clientConfiguration.Transport.ServerAddress = serverAddress.String()
	clientConfiguration.Authentication.Token = token
	if mode == protocol.ManagementModeGoverned {
		serverConfiguration.GovernedClients = map[string]config.GovernedClientConfig{
			clientConfiguration.Authentication.ClientID: {
				Authentication: config.ClientAuthenticationConfig{
					ClientID: clientConfiguration.Authentication.ClientID, Token: token,
				},
				Permissions: config.GovernedPermissions{
					Proxies: config.GovernedProxyPermissions{Limits: config.DefaultProxyPermissionLimits()},
					Forwards: config.GovernedForwardPermissions{
						Rules: loopbackForwardPolicy().Rules,
						Limits: config.DefaultForwardPermissionLimits(),
					},
				},
			},
		}
		clientConfiguration.Forwards = []config.ForwardConfig{forward}
	} else {
		serverConfiguration.ManagedClients = map[string]config.ManagedClientConfig{
			clientConfiguration.Authentication.ClientID: {
				Authentication: config.ClientAuthenticationConfig{
					ClientID: clientConfiguration.Authentication.ClientID, Token: token,
				},
				Permissions:   config.ManagedPermissions{Forwards: config.ForwardRules{Rules: loopbackForwardPolicy().Rules}},
				Configuration: config.ManagedConfiguration{Revision: 1, Proxies: []config.ProxyConfig{}, Forwards: []config.ForwardConfig{forward}},
			},
		}
	}
	cancelServer, serverErrors, cancelClient, clientErrors := runForwardServices(t, serverConfiguration, clientConfiguration)
	visitor := dialWithRetry(t, listenAddress.String(), 10*time.Second)
	message := []byte("portway restricted TCP Forward")
	_, _ = visitor.Write(message)
	response := make([]byte, len(message))
	if _, err := io.ReadFull(visitor, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != string(message) {
		t.Fatalf("unexpected %s Forward response %q", mode, response)
	}
	visitor.Close()
	stopForwardServices(t, cancelClient, clientErrors, cancelServer, serverErrors)
}

func loopbackForwardPolicy() config.ForwardServerConfig {
	ports := []config.PortRange{{Start: 1, End: 65535}}
	return config.ForwardServerConfig{Enabled: true, Rules: []config.ForwardIPRule{{
		IPRange: "127.0.0.1/32",
		TCP:     config.ForwardPortPermission{PortRanges: ports},
		UDP:     config.ForwardPortPermission{PortRanges: ports},
	}}}
}

func runForwardServices(
	t *testing.T,
	serverConfiguration config.ServerConfig,
	clientConfiguration config.ClientConfig,
) (context.CancelFunc, chan error, context.CancelFunc, chan error) {
	t.Helper()
	serverContext, cancelServer := context.WithCancel(context.Background())
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- NewService(logging.New("test-forward-server"), serverConfiguration).Run(serverContext)
	}()
	clientContext, cancelClient := context.WithCancel(context.Background())
	clientErrors := make(chan error, 1)
	go func() {
		clientErrors <- client.NewService(logging.New("test-forward-client"), clientConfiguration).Run(clientContext)
	}()
	return cancelServer, serverErrors, cancelClient, clientErrors
}

func stopForwardServices(
	t *testing.T,
	cancelClient context.CancelFunc,
	clientErrors chan error,
	cancelServer context.CancelFunc,
	serverErrors chan error,
) {
	t.Helper()
	cancelClient()
	if err := waitServiceResult(clientErrors); err != nil {
		t.Fatalf("Forward client stopped with error: %v", err)
	}
	cancelServer()
	if err := waitServiceResult(serverErrors); err != nil {
		t.Fatalf("Forward server stopped with error: %v", err)
	}
}
