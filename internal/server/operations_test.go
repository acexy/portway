package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/logging"
	proxyregistry "github.com/acexy/portway/internal/proxy/registry"
)

func TestOperationsEndpointsReportLifecycleAndLowCardinalityMetrics(t *testing.T) {
	configuration := config.DefaultServer()
	service := NewService(logging.New("operations-test"), configuration)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service.linkBroker = link.NewBroker(ctx)
	service.proxyRegistry = proxyregistry.NewConfigured(
		ctx,
		logging.New("operations-proxy-test"),
		"127.0.0.1",
		service.linkBroker,
		false,
		false,
		configuration.Proxies.HTTP.HTTPConfig,
		configuration.Proxies.UDP,
	)
	defer service.proxyRegistry.Close()
	service.ready.Store(true)

	for _, testCase := range []struct {
		path       string
		statusCode int
		body       string
	}{
		{"/healthz", http.StatusOK, "ok\n"},
		{"/readyz", http.StatusOK, "ready\n"},
	} {
		request := httptest.NewRequest(http.MethodGet, testCase.path, nil)
		response := httptest.NewRecorder()
		service.operationsHandler().ServeHTTP(response, request)
		if response.Code != testCase.statusCode || response.Body.String() != testCase.body {
			t.Fatalf("GET %s = (%d, %q), want (%d, %q)", testCase.path, response.Code, response.Body.String(), testCase.statusCode, testCase.body)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	service.operationsHandler().ServeHTTP(response, request)
	body := response.Body.String()
	for _, expected := range []string{
		"portway_ready 1\n",
		"portway_configuration_generation 1\n",
		"portway_sessions_active 0\n",
		"portway_links_pending 0\n",
		"portway_udp_associations 0\n",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("metrics do not contain %q:\n%s", expected, body)
		}
	}
	if strings.Contains(body, "client_id") || strings.Contains(body, "proxy_name") {
		t.Fatalf("metrics contain a prohibited high-cardinality identity:\n%s", body)
	}
}

func TestOperationsReadinessFailsClosedBeforeInitialization(t *testing.T) {
	service := NewService(logging.New("operations-test"), config.DefaultServer())
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	service.operationsHandler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Body.String() != "not ready\n" {
		t.Fatalf("readiness = (%d, %q), want (503, %q)", response.Code, response.Body.String(), "not ready\n")
	}
}
