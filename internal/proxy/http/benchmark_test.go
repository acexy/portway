package http

import (
	"context"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/acexy/portway/internal/link"
)

type benchmarkRoundTripper func(*stdhttp.Request) (*stdhttp.Response, error)

func (roundTrip benchmarkRoundTripper) RoundTrip(request *stdhttp.Request) (*stdhttp.Response, error) {
	return roundTrip(request)
}

func BenchmarkHTTPProxy(b *testing.B) {
	ctx, cancel := context.WithCancel(b.Context())
	broker := link.NewBroker(ctx)
	binding := NewBinding(
		ctx,
		defaultBenchmarkHTTPConfiguration(),
		"benchmark-binding",
		"app.example.com",
		broker,
		NewConnectionLimiter(1),
		nil,
	)
	binding.proxy.Transport = benchmarkRoundTripper(func(request *stdhttp.Request) (*stdhttp.Response, error) {
		return &stdhttp.Response{
			StatusCode:    stdhttp.StatusOK,
			Header:        make(stdhttp.Header),
			Body:          io.NopCloser(strings.NewReader("portway")),
			ContentLength: 7,
			Request:       request,
		}, nil
	})
	b.Cleanup(func() {
		binding.Close()
		cancel()
		broker.Close()
	})

	b.ReportAllocs()
	for b.Loop() {
		request := httptest.NewRequest(stdhttp.MethodGet, "http://app.example.com/resource?q=1", nil)
		request.Header.Set("X-Forwarded-For", "untrusted")
		response := httptest.NewRecorder()
		binding.ServeHTTP(response, request)
		if response.Code != stdhttp.StatusOK {
			b.Fatalf("unexpected status %d", response.Code)
		}
	}
}
