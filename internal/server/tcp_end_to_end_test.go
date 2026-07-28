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
		ListenAddress: serverAddress.String(),
		ProxyBindIP:   "127.0.0.1",
		LogLevel:      config.LogLevelInfo,
		Authentication: config.AuthenticationConfig{
			Mode:  config.AuthenticationModeToken,
			Token: token,
		},
	})
	go func() {
		serverErrors <- serverService.Run(serverContext)
	}()

	clientContext, cancelClient := context.WithCancel(context.Background())
	clientErrors := make(chan error, 1)
	clientService := client.NewService(logging.New("test-client"), config.ClientConfig{
		ClientID:      "end-to-end-client",
		ServerAddress: serverAddress.String(),
		LogLevel:      config.LogLevelInfo,
		Authentication: config.AuthenticationConfig{
			Mode:  config.AuthenticationModeToken,
			Token: token,
		},
		Proxies: []config.ProxyConfig{
			{
				Name:       "echo",
				Type:       "tcp",
				LocalIP:    "127.0.0.1",
				LocalPort:  uint16(echoAddress.Port),
				RemotePort: proxyPort,
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

func reserveTCPAddress(t *testing.T) *net.TCPAddr {
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

func dialWithRetry(t *testing.T, address string, timeout time.Duration) net.Conn {
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
