package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/acexy/portway/internal/client"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
)

func TestHTTPProxyEndToEnd(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host != "app.example.com" {
			t.Errorf("unexpected backend Host %q", request.Host)
		}
		if request.Header.Get("X-Portway-Test") != "preserved" {
			t.Errorf("end-to-end header was not preserved")
		}
		if request.Header.Get("X-Forwarded-Proto") != "http" {
			t.Errorf("unexpected forwarded proto %q", request.Header.Get("X-Forwarded-Proto"))
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read backend request body: %v", err)
			return
		}
		writer.Header().Set("X-Backend", "reached")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write(body)
	}))
	defer backend.Close()
	backendAddress := backend.Listener.Addr().(*net.TCPAddr)

	serverAddress := reserveTCPAddress(t)
	httpAddress := reserveTCPAddress(t)
	token := "test-token-with-at-least-32-random-bytes"
	serverContext, cancelServer := context.WithCancel(context.Background())
	serverErrors := make(chan error, 1)
	serverConfiguration := config.DefaultServer()
	serverConfiguration.Transport.ListenAddress = serverAddress.String()
	serverConfiguration.Proxies.HTTP.ListenAddress = httpAddress.String()
	serverConfiguration.Proxies.BindIP = "127.0.0.1"
	serverConfiguration.Authentication.SharedToken = &token
	serverService := NewService(logging.New("test-http-server"), serverConfiguration)
	go func() { serverErrors <- serverService.Run(serverContext) }()

	clientContext, cancelClient := context.WithCancel(context.Background())
	clientErrors := make(chan error, 1)
	clientConfiguration := config.DefaultClient()
	clientConfiguration.Authentication.ClientID = "http-end-to-end-client"
	clientConfiguration.Transport.ServerAddress = serverAddress.String()
	clientConfiguration.Authentication.Token = token
	clientConfiguration.Proxies = []config.ProxyConfig{{
		Name: "web", Type: "http",
		Local: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(backendAddress.Port)},
		Public: config.ProxyPublicConfig{Domain: "app.example.com",
			Schemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
	}}
	clientService := client.NewService(logging.New("test-http-client"), clientConfiguration)
	go func() { clientErrors <- clientService.Run(clientContext) }()

	var response *http.Response
	deadline := time.Now().Add(10 * time.Second)
	for {
		request, err := http.NewRequest(
			http.MethodPost,
			"http://"+httpAddress.String()+"/stream?q=1",
			strings.NewReader("portway HTTP end-to-end"),
		)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "app.example.com"
		request.Header.Set("X-Portway-Test", "preserved")
		request.Header.Set("X-Forwarded-Proto", "attacker-controlled")
		response, err = http.DefaultClient.Do(request)
		if err == nil && response.StatusCode == http.StatusCreated {
			break
		}
		if response != nil {
			response.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("HTTP proxy did not become ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "portway HTTP end-to-end" ||
		response.Header.Get("X-Backend") != "reached" {
		t.Fatalf("unexpected HTTP proxy response: header=%q body=%q",
			response.Header.Get("X-Backend"), body)
	}

	cancelClient()
	if err := waitServiceResult(clientErrors); err != nil {
		t.Fatalf("client stopped with error: %v", err)
	}
	cancelServer()
	if err := waitServiceResult(serverErrors); err != nil {
		t.Fatalf("server stopped with error: %v", err)
	}
}

func TestHTTPSProxyEndToEnd(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host != "secure.example.com" {
			t.Errorf("unexpected backend Host %q", request.Host)
		}
		if request.Header.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("unexpected forwarded proto %q", request.Header.Get("X-Forwarded-Proto"))
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("portway HTTPS end-to-end"))
	}))
	defer backend.Close()
	backendAddress := backend.Listener.Addr().(*net.TCPAddr)

	certificateFile, keyFile := writeServerCertificateForDNSNames(t, "secure.example.com")
	certificatePEM, err := os.ReadFile(certificateFile)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificates := x509.NewCertPool()
	if !rootCertificates.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("append HTTPS test certificate")
	}

	serverAddress := reserveTCPAddress(t)
	httpsAddress := reserveTCPAddress(t)
	token := "test-token-with-at-least-32-random-bytes"
	serverContext, cancelServer := context.WithCancel(context.Background())
	serverErrors := make(chan error, 1)
	serverConfiguration := config.DefaultServer()
	serverConfiguration.Transport.ListenAddress = serverAddress.String()
	serverConfiguration.Proxies.HTTPS.ListenAddress = httpsAddress.String()
	serverConfiguration.Proxies.BindIP = "127.0.0.1"
	serverConfiguration.Proxies.HTTPS.Certificates = []config.HTTPSCertificateConfig{{
		Domains:  []string{"secure.example.com"},
		CertFile: certificateFile,
		KeyFile:  keyFile,
	}}
	serverConfiguration.Authentication.SharedToken = &token
	serverService := NewService(logging.New("test-https-server"), serverConfiguration)
	go func() { serverErrors <- serverService.Run(serverContext) }()

	clientContext, cancelClient := context.WithCancel(context.Background())
	clientErrors := make(chan error, 1)
	clientConfiguration := config.DefaultClient()
	clientConfiguration.Authentication.ClientID = "https-end-to-end-client"
	clientConfiguration.Transport.ServerAddress = serverAddress.String()
	clientConfiguration.Authentication.Token = token
	clientConfiguration.Proxies = []config.ProxyConfig{{
		Name: "secure-web", Type: "http",
		Local: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(backendAddress.Port)},
		Public: config.ProxyPublicConfig{Domain: "secure.example.com",
			Schemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTPS}},
	}}
	clientService := client.NewService(logging.New("test-https-client"), clientConfiguration)
	go func() { clientErrors <- clientService.Run(clientContext) }()

	httpClient := &http.Client{Transport: &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCertificates,
			ServerName: "secure.example.com",
		},
	}}
	var response *http.Response
	deadline := time.Now().Add(10 * time.Second)
	for {
		request, requestError := http.NewRequest(
			http.MethodGet,
			"https://"+httpsAddress.String()+"/secure",
			nil,
		)
		if requestError != nil {
			t.Fatal(requestError)
		}
		request.Host = "secure.example.com"
		request.Header.Set("X-Forwarded-Proto", "attacker-controlled")
		response, err = httpClient.Do(request)
		if err == nil && response.StatusCode == http.StatusOK {
			break
		}
		if response != nil {
			response.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("HTTPS proxy did not become ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "portway HTTPS end-to-end" {
		t.Fatalf("unexpected HTTPS proxy body %q", body)
	}
	if response.ProtoMajor != 2 {
		t.Fatalf("HTTPS listener negotiated %q, want HTTP/2", response.Proto)
	}

	cancelClient()
	if err := waitServiceResult(clientErrors); err != nil {
		t.Fatalf("client stopped with error: %v", err)
	}
	cancelServer()
	if err := waitServiceResult(serverErrors); err != nil {
		t.Fatalf("server stopped with error: %v", err)
	}
}

func waitServiceResult(results <-chan error) error {
	select {
	case err := <-results:
		return err
	case <-time.After(5 * time.Second):
		return context.DeadlineExceeded
	}
}
