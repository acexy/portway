package server

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/client"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/transport"
)

func TestTCPProxyEndToEnd(t *testing.T) {
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	echoAddress := echoListener.Addr().(*net.TCPAddr)
	echoContext, cancelEcho := context.WithCancel(context.Background())
	defer cancelEcho()
	go runEchoServer(echoContext, echoListener)

	serverAddress := reserveTCPAddress(t)
	proxyAddress := reserveTCPAddress(t)
	proxyPort := uint16(proxyAddress.Port)
	token := "test-token-with-at-least-32-random-bytes"

	serverContext, cancelServer := context.WithCancel(context.Background())
	serverErrors := make(chan error, 1)
	serverService := NewService(logging.New("test-server"), config.ServerConfig{
		Transport: config.ServerTransportConfig{
			Type:          transport.TypeTCP,
			ListenAddress: serverAddress.String(),
		},
		Proxies: config.ServerProxyConfig{
			BindIP: "127.0.0.1",
			HTTP:  config.DefaultServer().Proxies.HTTP,
			UDP:   config.DefaultServer().Proxies.UDP,
		},
		LogLevel: config.LogLevelInfo,
		Authentication: config.ServerAuthenticationConfig{
			SharedToken: &token,
		},
	})
	go func() {
		serverErrors <- serverService.Run(serverContext)
	}()

	clientContext, cancelClient := context.WithCancel(context.Background())
	clientErrors := make(chan error, 1)
	clientService := client.NewService(logging.New("test-client"), config.ClientConfig{
		Transport: config.ClientTransportConfig{
			Type:          transport.TypeTCP,
			ServerAddress: serverAddress.String(),
		},
		LogLevel: config.LogLevelInfo,
		Authentication: config.ClientAuthenticationConfig{
			ClientID: "end-to-end-client",
			Token:    token,
		},
		Proxies: []config.ProxyConfig{
			{
				Name:   "echo",
				Type:   "tcp",
				Local:  config.EndpointConfig{IP: "127.0.0.1", Port: uint16(echoAddress.Port)},
				Public: config.ProxyPublicConfig{Port: proxyPort},
			},
		},
	})
	go func() {
		clientErrors <- clientService.Run(clientContext)
	}()

	visitor := dialWithRetry(t, proxyAddress.String(), 10*time.Second)
	message := []byte("portway TCP end-to-end")
	if _, err := visitor.Write(message); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(message))
	if _, err := io.ReadFull(visitor, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != string(message) {
		t.Fatalf("unexpected proxy response %q", response)
	}
	visitor.Close()

	cancelClient()
	select {
	case err := <-clientErrors:
		if err != nil {
			t.Fatalf("client stopped with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client did not stop")
	}

	cancelServer()
	select {
	case err := <-serverErrors:
		if err != nil {
			t.Fatalf("server stopped with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestTCPMultiModeAuthenticationEndToEnd(t *testing.T) {
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	echoAddress := echoListener.Addr().(*net.TCPAddr)
	echoContext, cancelEcho := context.WithCancel(context.Background())
	defer cancelEcho()
	go runEchoServer(echoContext, echoListener)

	serverAddress := reserveTCPAddress(t)
	sharedProxyAddress := reserveTCPAddress(t)
	governedProxyAddress := reserveTCPAddress(t)
	managedProxyAddress := reserveTCPAddress(t)
	sharedToken := "shared-token-with-at-least-32-random-bytes"
	governedToken := "governed-token-with-at-least-32-random-bytes"
	managedToken := "managed-token-with-at-least-32-random-bytes"

	serverConfiguration := config.DefaultServer()
	serverConfiguration.Transport.ListenAddress = serverAddress.String()
	serverConfiguration.Proxies.BindIP = "127.0.0.1"
	serverConfiguration.Authentication.SharedToken = &sharedToken
	serverConfiguration.GovernedClients = map[string]config.GovernedClientConfig{
		"governed-authority": {
			Authentication: config.ClientAuthenticationConfig{ClientID: "governed-authority", Token: governedToken},
			Permissions: config.GovernedPermissions{
				Proxies: config.GovernedProxyPermissions{
					TCP: &config.ProxyPermission{RemotePortRanges: []config.PortRange{{
						Start: uint16(governedProxyAddress.Port),
						End:   uint16(governedProxyAddress.Port),
					}}},
					Limits: config.ProxyPermissionLimits{MaxTotal: 1},
				},
			},
		},
	}
	serverConfiguration.ManagedClients = map[string]config.ManagedClientConfig{
		"managed-authority": {
			Authentication: config.ClientAuthenticationConfig{ClientID: "managed-authority", Token: managedToken},
			Configuration: config.ManagedConfiguration{
				Revision: 1,
				Proxies: []config.ProxyConfig{{
					Name:   "managed-echo",
					Type:   "tcp",
					Local:  config.EndpointConfig{IP: "127.0.0.1", Port: uint16(echoAddress.Port)},
					Public: config.ProxyPublicConfig{Port: uint16(managedProxyAddress.Port)},
				}},
			},
		},
	}

	serverContext, cancelServer := context.WithCancel(context.Background())
	serverErrors := make(chan error, 1)
	serverService := NewService(logging.New("test-multi-mode-server"), serverConfiguration)
	go func() {
		serverErrors <- serverService.Run(serverContext)
	}()

	type runningClient struct {
		cancel context.CancelFunc
		errors chan error
	}
	startClient := func(configuration config.ClientConfig) runningClient {
		clientContext, cancel := context.WithCancel(context.Background())
		errors := make(chan error, 1)
		service := client.NewService(logging.New("test-multi-mode-client"), configuration)
		go func() {
			errors <- service.Run(clientContext)
		}()
		return runningClient{cancel: cancel, errors: errors}
	}
	clientConfiguration := func(
		clientID string,
		token string,
		proxies []config.ProxyConfig,
	) config.ClientConfig {
		configuration := config.DefaultClient()
		configuration.Authentication.ClientID = clientID
		configuration.Transport.ServerAddress = serverAddress.String()
		configuration.Authentication.Token = token
		configuration.Proxies = proxies
		return configuration
	}

	clients := []runningClient{
		startClient(clientConfiguration(
			"shared-instance",
			sharedToken,
			[]config.ProxyConfig{{
				Name:   "shared-echo",
				Type:   "tcp",
				Local:  config.EndpointConfig{IP: "127.0.0.1", Port: uint16(echoAddress.Port)},
				Public: config.ProxyPublicConfig{Port: uint16(sharedProxyAddress.Port)},
			}},
		)),
		startClient(clientConfiguration(
			"governed-authority",
			governedToken,
			[]config.ProxyConfig{{
				Name:   "governed-echo",
				Type:   "tcp",
				Local:  config.EndpointConfig{IP: "127.0.0.1", Port: uint16(echoAddress.Port)},
				Public: config.ProxyPublicConfig{Port: uint16(governedProxyAddress.Port)},
			}},
		)),
		startClient(clientConfiguration(
			"managed-authority",
			managedToken,
			nil,
		)),
	}

	for name, address := range map[string]string{
		"shared":   sharedProxyAddress.String(),
		"governed": governedProxyAddress.String(),
		"managed":  managedProxyAddress.String(),
	} {
		connection := dialWithRetry(t, address, 10*time.Second)
		message := []byte("multi-mode-" + name)
		if _, err := connection.Write(message); err != nil {
			connection.Close()
			t.Fatal(err)
		}
		response := make([]byte, len(message))
		if _, err := io.ReadFull(connection, response); err != nil {
			connection.Close()
			t.Fatal(err)
		}
		connection.Close()
		if string(response) != string(message) {
			t.Fatalf("%s proxy returned %q", name, response)
		}
	}

	for _, running := range clients {
		running.cancel()
	}
	for _, running := range clients {
		if err := waitServiceResult(running.errors); err != nil {
			t.Fatalf("client stopped with error: %v", err)
		}
	}
	cancelServer()
	if err := waitServiceResult(serverErrors); err != nil {
		t.Fatalf("server stopped with error: %v", err)
	}
}

func reserveTCPAddress(t testing.TB) *net.TCPAddr {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().(*net.TCPAddr)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func dialWithRetry(t testing.TB, address string, timeout time.Duration) net.Conn {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		connection, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			return connection
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial %s: %v", address, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func runEchoServer(ctx context.Context, listener net.Listener) {
	stopContextClose := context.AfterFunc(ctx, func() {
		listener.Close()
	})
	defer stopContextClose()

	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		go func() {
			defer connection.Close()
			_, _ = io.Copy(connection, connection)
		}()
	}
}
