package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/acexy/portway/internal/client"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
)

func TestHTTPProxyEndToEnd(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host != "app.example.com" {
			t.Errorf("unexpected backend Host %q", request.Host)
		}
		if request.Header.Get("X-Portway-Test") != "preserved" {
			t.Errorf("end-to-end header was not preserved")
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
	serverConfiguration.Tunnel.HTTPListenAddress = httpAddress.String()
	serverConfiguration.Tunnel.BindIP = "127.0.0.1"
	serverConfiguration.Authentication.SharedToken = &token
	serverService := NewService(logging.New("test-http-server"), serverConfiguration)
	go func() { serverErrors <- serverService.Run(serverContext) }()

	clientContext, cancelClient := context.WithCancel(context.Background())
	clientErrors := make(chan error, 1)
	clientConfiguration := config.DefaultClient()
	clientConfiguration.ClientID = "http-end-to-end-client"
	clientConfiguration.Transport.ServerAddress = serverAddress.String()
	clientConfiguration.Authentication.Token = token
	clientConfiguration.Proxies = []config.ProxyConfig{{
		Name: "web", Type: "http", Domain: "app.example.com",
		LocalIP: "127.0.0.1", LocalPort: uint16(backendAddress.Port),
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

func waitServiceResult(results <-chan error) error {
	select {
	case err := <-results:
		return err
	case <-time.After(5 * time.Second):
		return context.DeadlineExceeded
	}
}
