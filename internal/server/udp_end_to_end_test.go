package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/client"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

func TestUDPProxyOverTCPTransportEndToEnd(t *testing.T) {
	runUDPProxyEndToEnd(t, transport.TypeTCP)
}

func TestUDPProxyOverQUICTransportEndToEnd(t *testing.T) {
	runUDPProxyEndToEnd(t, transport.TypeQUIC)
}

func TestUDPMirrorProxyEndToEnd(t *testing.T) {
	primaryConnection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer primaryConnection.Close()
	primaryContext, cancelPrimary := context.WithCancel(context.Background())
	defer cancelPrimary()
	go runUDPEchoServer(primaryContext, primaryConnection)

	mirrorConnection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer mirrorConnection.Close()
	mirrorReceived := make(chan []byte, 32)
	go func() {
		buffer := make([]byte, 1024)
		for {
			length, source, readError := mirrorConnection.ReadFromUDP(buffer)
			if readError != nil {
				return
			}
			mirrorReceived <- append([]byte(nil), buffer[:length]...)
			_, _ = mirrorConnection.WriteToUDP([]byte("mirror-response"), source)
		}
	}()

	serverAddress := reserveTCPAddress(t).String()
	proxyAddress := reserveUDPAddress(t)
	proxyPort := uint16(proxyAddress.Port)
	primaryToken := "udp-primary-token-with-at-least-32-random-bytes"
	mirrorToken := "udp-mirror-token-with-at-least-32-random-bytes"
	serverConfiguration := config.DefaultServer()
	serverConfiguration.Transport.ListenAddress = serverAddress
	serverConfiguration.Proxies.BindIP = "127.0.0.1"
	serverConfiguration.Authentication.SharedToken = nil
	permission := func(clientID string, token string) config.GovernedClientConfig {
		return config.GovernedClientConfig{
			Authentication: config.ClientAuthenticationConfig{ClientID: clientID, Token: token},
			Permissions: config.GovernedPermissions{Proxies: config.GovernedProxyPermissions{
				UDP:    &config.ProxyPermission{PortRanges: []config.PortRange{{Start: proxyPort, End: proxyPort}}},
				Limits: config.DefaultProxyPermissionLimits(),
			}},
		}
	}
	serverConfiguration.GovernedClients = map[string]config.GovernedClientConfig{
		"primary-client": permission("primary-client", primaryToken),
		"mirror-client":  permission("mirror-client", mirrorToken),
	}
	serverConfiguration.Proxies.Mirror.Governed = []config.ProxyMirrorGroupConfig{{
		Name: "udp-mirror", Type: "udp", Public: mirrorPublicConfig(proxyPort),
		PrimaryClientID: "primary-client", ClientIDs: []string{"primary-client", "mirror-client"},
	}}

	serverContext, cancelServer := context.WithCancel(context.Background())
	serverErrors := make(chan error, 1)
	serverService := NewService(logging.New("test-udp-mirror-server"), serverConfiguration)
	go func() { serverErrors <- serverService.Run(serverContext) }()

	type runningClient struct {
		cancel context.CancelFunc
		errors chan error
	}
	startClient := func(clientID string, token string, localPort uint16) runningClient {
		ctx, cancel := context.WithCancel(context.Background())
		errors := make(chan error, 1)
		configuration := config.DefaultClient()
		configuration.Transport.ServerAddress = serverAddress
		configuration.Authentication = config.ClientAuthenticationConfig{ClientID: clientID, Token: token}
		configuration.Proxies = []config.ProxyConfig{{
			Name: clientID + "-udp", Type: "udp",
			Local:  config.EndpointConfig{IP: "127.0.0.1", Port: localPort},
			Public: config.ProxyPublicConfig{Port: proxyPort},
		}}
		service := client.NewService(logging.New("test-udp-mirror-client"), configuration)
		go func() { errors <- service.Run(ctx) }()
		return runningClient{cancel: cancel, errors: errors}
	}
	clients := []runningClient{
		startClient("primary-client", primaryToken, uint16(primaryConnection.LocalAddr().(*net.UDPAddr).Port)),
	}
	waitForMirrorMembers(
		t,
		serverService,
		serverErrors,
		clients[0].errors,
		nil,
		protocol.ProxyTypeUDP,
		1,
	)
	clients = append(
		clients,
		startClient("mirror-client", mirrorToken, uint16(mirrorConnection.LocalAddr().(*net.UDPAddr).Port)),
	)
	waitForMirrorMembers(
		t,
		serverService,
		serverErrors,
		clients[0].errors,
		clients[1].errors,
		protocol.ProxyTypeUDP,
		2,
	)

	visitor, err := net.DialUDP("udp", nil, proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer visitor.Close()
	payload := []byte("udp-mirror-payload")
	response := make([]byte, 1024)
	deadline := time.Now().Add(20 * time.Second)
	primaryResponded := false
	mirrorObserved := false
	for {
		if _, err := visitor.Write(payload); err != nil {
			t.Fatal(err)
		}
		_ = visitor.SetReadDeadline(time.Now().Add(time.Second))
		length, _, readError := visitor.ReadFromUDP(response)
		if readError == nil {
			if string(response[:length]) != string(payload) {
				t.Fatalf("visitor received non-primary response %q", response[:length])
			}
			primaryResponded = true
		}
		select {
		case mirrored := <-mirrorReceived:
			if string(mirrored) != string(payload) {
				t.Fatalf("mirror received %q", mirrored)
			}
			mirrorObserved = true
		default:
		}
		if primaryResponded && mirrorObserved {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP mirror did not become ready: %v", readError)
		}
	}
	for {
		select {
		case <-mirrorReceived:
		default:
			goto mirrorQueueDrained
		}
	}

mirrorQueueDrained:
	clients[1].cancel()
	if err := waitServiceResult(clients[1].errors); err != nil {
		t.Fatalf("UDP mirror client stopped with error: %v", err)
	}
	waitForMirrorMembers(
		t,
		serverService,
		serverErrors,
		clients[0].errors,
		nil,
		protocol.ProxyTypeUDP,
		1,
	)
	rejoined := startClient(
		"mirror-client",
		mirrorToken,
		uint16(mirrorConnection.LocalAddr().(*net.UDPAddr).Port),
	)
	waitForMirrorMembers(
		t,
		serverService,
		serverErrors,
		clients[0].errors,
		rejoined.errors,
		protocol.ProxyTypeUDP,
		2,
	)
	rejoinPayload := []byte("udp-mirror-rejoin-payload")
	deadline = time.Now().Add(20 * time.Second)
	for {
		if _, err := visitor.Write(rejoinPayload); err != nil {
			t.Fatal(err)
		}
		_ = visitor.SetReadDeadline(time.Now().Add(time.Second))
		length, _, readError := visitor.ReadFromUDP(response)
		if readError == nil && string(response[:length]) != string(rejoinPayload) {
			t.Fatalf("visitor received non-primary response after rejoin %q", response[:length])
		}
		select {
		case mirrored := <-mirrorReceived:
			if string(mirrored) == string(rejoinPayload) {
				goto rejoinedMirrorObserved
			}
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("rejoined UDP mirror did not receive live visitor datagram: %v", readError)
		}
	}

rejoinedMirrorObserved:

	clients[0].cancel()
	rejoined.cancel()
	for _, running := range []runningClient{clients[0], rejoined} {
		if err := waitServiceResult(running.errors); err != nil {
			t.Fatalf("UDP mirror client stopped with error: %v", err)
		}
	}
	cancelServer()
	if err := waitServiceResult(serverErrors); err != nil {
		t.Fatalf("UDP mirror server stopped with error: %v", err)
	}
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
