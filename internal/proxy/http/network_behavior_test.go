package http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
)

// Exercise the production ReverseProxy over real public and backend sockets.
// Link authentication and admission are covered by the server end-to-end tests.
func newNetworkBehaviorProxy(t *testing.T, backend *httptest.Server) (*Binding, *httptest.Server, <-chan RequestResult) {
	t.Helper()
	binding, cleanup := newTestBinding(t, config.DefaultServer().Proxies.HTTP.HTTPConfig)
	t.Cleanup(cleanup)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
	}
	binding.transport.DialContext = dial
	binding.upgradeTransport.DialContext = dial
	results := make(chan RequestResult, 1)
	public := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		results <- binding.ServeHTTPResult(writer, request)
	}))
	t.Cleanup(public.Close)
	return binding, public, results
}

func TestReverseProxyNetworkStreamingTrailersAndInformationalStatus(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	backend := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil || string(body) != "request" || request.Trailer.Get("X-Request-End") != "complete" {
			t.Errorf("request/trailer mismatch: body=%q trailer=%v err=%v", body, request.Trailer, err)
		}
		writer.WriteHeader(stdhttp.StatusEarlyHints)
		writer.Header().Set("Trailer", "X-Response-End")
		writer.WriteHeader(stdhttp.StatusCreated)
		_, _ = io.WriteString(writer, "first")
		if err := stdhttp.NewResponseController(writer).Flush(); err != nil {
			t.Error(err)
			return
		}
		<-release
		_, _ = io.WriteString(writer, "last")
		writer.Header().Set("X-Response-End", "complete")
	}))
	t.Cleanup(backend.Close)
	_, public, results := newNetworkBehaviorProxy(t, backend)
	t.Cleanup(unblock)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodPost, public.URL, strings.NewReader("request"))
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = -1
	request.Trailer = stdhttp.Header{"X-Request-End": {"complete"}}
	request.Header.Set("Expect", "100-continue")
	var informational []int
	request = request.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		Got1xxResponse: func(code int, _ textproto.MIMEHeader) error { informational = append(informational, code); return nil },
	}))
	response, err := public.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	first := make([]byte, 5)
	if _, err := io.ReadFull(response.Body, first); err != nil || string(first) != "first" {
		t.Fatalf("streamed prefix = %q, err=%v", first, err)
	}
	// The backend cannot finish until the first chunk reaches the public client.
	unblock()
	rest, err := io.ReadAll(response.Body)
	if err != nil || string(rest) != "last" || response.StatusCode != stdhttp.StatusCreated || response.Trailer.Get("X-Response-End") != "complete" {
		t.Fatalf("response=%+v rest=%q err=%v", response, rest, err)
	}
	seenHints := false
	for _, code := range informational {
		if code == stdhttp.StatusEarlyHints {
			seenHints = true
		}
	}
	if !seenHints {
		t.Fatal("103 response was not forwarded")
	}
	select {
	case result := <-results:
		if result.StatusCode != stdhttp.StatusCreated || result.ErrorCode != "" {
			t.Fatalf("summary=%+v", result)
		}
	case <-ctx.Done():
		t.Fatal("proxy handler did not finish")
	}
}

func TestReverseProxyNetworkUpgradeAndBindingCancellation(t *testing.T) {
	backendDone := make(chan struct{})
	backend := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		defer close(backendDone)
		connection, buffer, err := stdhttp.NewResponseController(writer).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Error(err)
			return
		}
		_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: portway-test\r\n\r\n")
		if err := buffer.Flush(); err != nil {
			t.Error(err)
			return
		}
		_, _ = io.Copy(connection, buffer)
	}))
	t.Cleanup(backend.Close)
	binding, public, results := newNetworkBehaviorProxy(t, backend)
	connection, err := net.DialTimeout("tcp", public.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Fprintf(connection, "GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: Upgrade\r\nUpgrade: portway-test\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := stdhttp.ReadResponse(reader, &stdhttp.Request{Method: stdhttp.MethodGet})
	if err != nil || response.StatusCode != stdhttp.StatusSwitchingProtocols {
		t.Fatalf("Upgrade response=%v err=%v", response, err)
	}
	if _, err := io.WriteString(connection, "echo"); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != "echo" {
		t.Fatalf("echo=%q err=%v", echo, err)
	}
	binding.Close()
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("Binding cancellation left upgraded connection open")
	} else {
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			t.Fatal("Binding cancellation did not close the connection before its deadline")
		}
	}
	select {
	case result := <-results:
		if result.StatusCode != stdhttp.StatusSwitchingProtocols {
			t.Fatalf("Upgrade summary=%+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Upgrade handler did not finish")
	}
	select {
	case <-backendDone:
	case <-time.After(5 * time.Second):
		t.Fatal("backend connection did not close")
	}
}
