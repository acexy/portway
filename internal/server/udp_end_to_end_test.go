package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/client"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/transport"
)

func TestUDPProxyOverTCPTransportEndToEnd(t *testing.T) {
	runUDPProxyEndToEnd(t, transport.TypeTCP)
}

func TestUDPProxyOverQUICTransportEndToEnd(t *testing.T) {
	runUDPProxyEndToEnd(t, transport.TypeQUIC)
}

func runUDPProxyEndToEnd(t *testing.T, transportType transport.Type) {
	t.Helper()
	echoConnection, err := net.ListenUDP("udp", &net.UDPAddr{
		IP: net.ParseIP("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer echoConnection.Close()
	echoAddress := echoConnection.LocalAddr().(*net.UDPAddr)
	echoContext, cancelEcho := context.WithCancel(context.Background())
	defer cancelEcho()
	go runUDPEchoServer(echoContext, echoConnection)

	var serverAddress string
	serverConfiguration := config.DefaultServer()
	clientConfiguration := config.DefaultClient()
	if transportType == transport.TypeQUIC {
		quicAddress := reserveUDPAddress(t)
		certificateFile, keyFile := writeQUICServerCertificate(t)
		serverAddress = quicAddress.String()
		serverConfiguration.Transport.Type = transport.TypeQUIC
		serverConfiguration.Transport.QUIC.CertFile = certificateFile
		serverConfiguration.Transport.QUIC.KeyFile = keyFile
		clientConfiguration.Transport.Type = transport.TypeQUIC
		clientConfiguration.Transport.QUIC.ServerName = "localhost"
		clientConfiguration.Transport.QUIC.CAFile = certificateFile
	} else {
		serverAddress = reserveTCPAddress(t).String()
	}
	proxyAddress := reserveUDPAddress(t)
	token := "test-token-with-at-least-32-random-bytes"
	serverConfiguration.Transport.ListenAddress = serverAddress
	serverConfiguration.Proxies.BindIP = "127.0.0.1"
	serverConfiguration.Authentication.SharedToken = &token

	serverContext, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	serverErrors := make(chan error, 1)
	serverService := NewService(
		logging.New("test-udp-server"),
		serverConfiguration,
	)
	go func() {
		serverErrors <- serverService.Run(serverContext)
	}()

	clientConfiguration.Authentication.ClientID = "udp-" + string(transportType) + "-client"
	clientConfiguration.Transport.ServerAddress = serverAddress
	clientConfiguration.Authentication.Token = token
	clientConfiguration.Proxies = []config.ProxyConfig{{
		Name:   "echo",
		Type:   "udp",
		Local:  config.EndpointConfig{IP: "127.0.0.1", Port: uint16(echoAddress.Port)},
		Public: config.ProxyPublicConfig{Port: uint16(proxyAddress.Port)},
	}}
	clientContext, cancelClient := context.WithCancel(context.Background())
	defer cancelClient()
	clientErrors := make(chan error, 1)
	clientService := client.NewService(
		logging.New("test-udp-client"),
		clientConfiguration,
	)
	go func() {
		clientErrors <- clientService.Run(clientContext)
	}()

	visitor, err := net.DialUDP("udp", nil, proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer visitor.Close()
	message := []byte("portway UDP over " + string(transportType))
	response := make([]byte, len(message))
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := visitor.Write(message); err != nil {
			t.Fatal(err)
		}
		if err := visitor.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		length, _, err := visitor.ReadFromUDP(response)
		if err == nil {
			if string(response[:length]) != string(message) {
				t.Fatalf("unexpected UDP response %q", response[:length])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP proxy over %s did not become ready: %v", transportType, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancelClient()
	if err := waitServiceResult(clientErrors); err != nil {
		t.Fatalf("UDP client stopped with error: %v", err)
	}
	cancelServer()
	if err := waitServiceResult(serverErrors); err != nil {
		t.Fatalf("UDP server stopped with error: %v", err)
	}
}

func runUDPEchoServer(ctx context.Context, connection *net.UDPConn) {
	stopContextClose := context.AfterFunc(ctx, func() {
		connection.Close()
	})
	defer stopContextClose()
	buffer := make([]byte, 65535)
	for {
		length, source, err := connection.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if _, err := connection.WriteToUDP(buffer[:length], source); err != nil {
			return
		}
	}
}
