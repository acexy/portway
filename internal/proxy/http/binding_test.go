package http

import (
	"context"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/security/ipfilter"
)

type timeoutRoundTripper func(*stdhttp.Request) (*stdhttp.Response, error)

func (roundTripper timeoutRoundTripper) RoundTrip(
	request *stdhttp.Request,
) (*stdhttp.Response, error) {
	return roundTripper(request)
}

type upstreamTimeoutError struct{}

func (upstreamTimeoutError) Error() string   { return "upstream response header timeout" }
func (upstreamTimeoutError) Timeout() bool   { return true }
func (upstreamTimeoutError) Temporary() bool { return true }

var _ net.Error = upstreamTimeoutError{}

func TestReverseProxyReturnsGatewayTimeoutForUpstreamTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	broker := link.NewBroker(ctx)
	binding := NewBinding(
		ctx,
		config.DefaultServer().HTTP,
		"binding-one",
		"app.example.com",
		broker,
		NewConnectionLimiter(1),
		nil,
	)
	binding.proxy.Transport = timeoutRoundTripper(
		func(*stdhttp.Request) (*stdhttp.Response, error) {
			return nil, upstreamTimeoutError{}
		},
	)
	t.Cleanup(func() {
		binding.Close()
		cancel()
		broker.Close()
	})

	request := httptest.NewRequest(
		stdhttp.MethodGet,
		"http://app.example.com/resource",
		nil,
	)
	response := httptest.NewRecorder()
	binding.ServeHTTP(response, request)
	if response.Code != stdhttp.StatusGatewayTimeout {
		t.Fatalf("response status = %d, want %d", response.Code, stdhttp.StatusGatewayTimeout)
	}
}

func TestReverseProxyForwardsValidatedClientIPChain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	broker := link.NewBroker(ctx)
	binding := NewBinding(
		ctx,
		config.DefaultServer().HTTP,
		"binding-one",
		"app.example.com",
		broker,
		NewConnectionLimiter(1),
		nil,
	)
	var forwardedFor string
	binding.proxy.Transport = timeoutRoundTripper(
		func(request *stdhttp.Request) (*stdhttp.Response, error) {
			forwardedFor = request.Header.Get("X-Forwarded-For")
			return &stdhttp.Response{
				StatusCode: stdhttp.StatusNoContent,
				Header:     make(stdhttp.Header),
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		},
	)
	t.Cleanup(func() {
		binding.Close()
		cancel()
		broker.Close()
	})

	rulesPath := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(rulesPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	filter, err := ipfilter.New(ctx, logging.New("http-forward-test"), rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Close()
	handler := ipfilter.HTTPHandler(filter, "X-Real-IP", binding)

	serverConnection, clientConnection := net.Pipe()
	defer serverConnection.Close()
	defer clientConnection.Close()
	request := httptest.NewRequest(
		stdhttp.MethodGet,
		"http://app.example.com/resource",
		nil,
	)
	request.Header.Set("X-Real-IP", "198.51.100.10, 203.0.113.20")
	request.Header.Set("X-Forwarded-For", "192.0.2.99")
	request = request.WithContext(
		ipfilter.HTTPConnectionContext(request.Context(), serverConnection),
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != stdhttp.StatusNoContent {
		t.Fatalf("response status = %d, want %d", response.Code, stdhttp.StatusNoContent)
	}
	if forwardedFor != "198.51.100.10, 203.0.113.20" {
		t.Fatalf("X-Forwarded-For = %q", forwardedFor)
	}
}
