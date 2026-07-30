package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/acexy/portway/internal/client"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/transport"
)

func TestHTTPProxyOverQUICEndToEnd(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read backend request body: %v", err)
			return
		}
		writer.Header().Set("X-Backend", "quic")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write(body)
	}))
	defer backend.Close()
	backendAddress := backend.Listener.Addr().(*net.TCPAddr)

	quicAddress := reserveUDPAddress(t)
	httpAddress := reserveTCPAddress(t)
	certificateFile, keyFile := writeQUICServerCertificate(t)
	token := "test-token-with-at-least-32-random-bytes"

	serverConfiguration := config.DefaultServer()
	serverConfiguration.Transport.Type = transport.TypeQUIC
	serverConfiguration.Transport.ListenAddress = quicAddress.String()
	serverConfiguration.Transport.QUIC.CertFile = certificateFile
	serverConfiguration.Transport.QUIC.KeyFile = keyFile
	serverConfiguration.Tunnel.BindIP = "127.0.0.1"
	serverConfiguration.Tunnel.HTTPListenAddress = httpAddress.String()
	serverConfiguration.Authentication.SharedToken = &token
	serverContext, cancelServer := context.WithCancel(context.Background())
	serverErrors := make(chan error, 1)
	serverService := NewService(logging.New("test-http-quic-server"), serverConfiguration)
	go func() {
		serverErrors <- serverService.Run(serverContext)
	}()

	clientConfiguration := config.DefaultClient()
	clientConfiguration.ClientID = "http-quic-end-to-end-client"
	clientConfiguration.Transport.Type = transport.TypeQUIC
	clientConfiguration.Transport.ServerAddress = quicAddress.String()
	clientConfiguration.Transport.QUIC.ServerName = "localhost"
	clientConfiguration.Transport.QUIC.CAFile = certificateFile
	clientConfiguration.Authentication.Token = token
	clientConfiguration.Proxies = []config.ProxyConfig{{
		Name:      "web",
		Type:      "http",
		Domain:    "app.example.com",
		LocalIP:   "127.0.0.1",
		LocalPort: uint16(backendAddress.Port),
	}}
	clientContext, cancelClient := context.WithCancel(context.Background())
	clientErrors := make(chan error, 1)
	clientService := client.NewService(logging.New("test-http-quic-client"), clientConfiguration)
	go func() {
		clientErrors <- clientService.Run(clientContext)
	}()

	var response *http.Response
	deadline := time.Now().Add(10 * time.Second)
	for {
		request, err := http.NewRequest(
			http.MethodPost,
			"http://"+httpAddress.String()+"/quic",
			strings.NewReader("HTTP over Portway QUIC"),
		)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "app.example.com"
		response, err = http.DefaultClient.Do(request)
		if err == nil && response.StatusCode == http.StatusCreated {
			break
		}
		if response != nil {
			response.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("HTTP over QUIC proxy did not become ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "HTTP over Portway QUIC" ||
		response.Header.Get("X-Backend") != "quic" {
		t.Fatalf("unexpected HTTP over QUIC response: header=%q body=%q",
			response.Header.Get("X-Backend"), body)
	}

	cancelClient()
	if err := waitServiceResult(clientErrors); err != nil {
		t.Fatalf("QUIC client stopped with error: %v", err)
	}
	cancelServer()
	if err := waitServiceResult(serverErrors); err != nil {
		t.Fatalf("QUIC server stopped with error: %v", err)
	}
}

func TestTCPProxyOverQUICEndToEnd(t *testing.T) {
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	echoAddress := echoListener.Addr().(*net.TCPAddr)
	echoContext, cancelEcho := context.WithCancel(context.Background())
	defer cancelEcho()
	go runEchoServer(echoContext, echoListener)

	quicAddress := reserveUDPAddress(t)
	proxyAddress := reserveTCPAddress(t)
	certificateFile, keyFile := writeQUICServerCertificate(t)
	token := "test-token-with-at-least-32-random-bytes"

	serverConfiguration := config.DefaultServer()
	serverConfiguration.Transport.Type = transport.TypeQUIC
	serverConfiguration.Transport.ListenAddress = quicAddress.String()
	serverConfiguration.Transport.QUIC.CertFile = certificateFile
	serverConfiguration.Transport.QUIC.KeyFile = keyFile
	serverConfiguration.Tunnel.BindIP = "127.0.0.1"
	serverConfiguration.Authentication.SharedToken = &token
	serverContext, cancelServer := context.WithCancel(context.Background())
	serverErrors := make(chan error, 1)
	serverService := NewService(logging.New("test-quic-server"), serverConfiguration)
	go func() {
		serverErrors <- serverService.Run(serverContext)
	}()

	clientConfiguration := config.DefaultClient()
	clientConfiguration.ClientID = "quic-end-to-end-client"
	clientConfiguration.Transport.Type = transport.TypeQUIC
	clientConfiguration.Transport.ServerAddress = quicAddress.String()
	clientConfiguration.Transport.QUIC.ServerName = "localhost"
	clientConfiguration.Transport.QUIC.CAFile = certificateFile
	clientConfiguration.Authentication.Token = token
	clientConfiguration.Proxies = []config.ProxyConfig{{
		Name:       "echo",
		Type:       "tcp",
		LocalIP:    "127.0.0.1",
		LocalPort:  uint16(echoAddress.Port),
		RemotePort: uint16(proxyAddress.Port),
	}}
	clientContext, cancelClient := context.WithCancel(context.Background())
	clientErrors := make(chan error, 1)
	clientService := client.NewService(logging.New("test-quic-client"), clientConfiguration)
	go func() {
		clientErrors <- clientService.Run(clientContext)
	}()

	visitor := dialWithRetry(t, proxyAddress.String(), 10*time.Second)
	message := []byte("portway TCP proxy over QUIC")
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
			t.Fatalf("QUIC client stopped with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("QUIC client did not stop")
	}
	cancelServer()
	select {
	case err := <-serverErrors:
		if err != nil {
			t.Fatalf("QUIC server stopped with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("QUIC server did not stop")
	}
}

func reserveUDPAddress(t *testing.T) *net.UDPAddr {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{
		IP: net.ParseIP("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	address := connection.LocalAddr().(*net.UDPAddr)
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func writeQUICServerCertificate(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificateFile := filepath.Join(directory, "server.crt")
	keyFile := filepath.Join(directory, "server.key")
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateDER,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificateFile, keyFile
}
