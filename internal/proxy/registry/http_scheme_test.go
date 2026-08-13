package registry

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
)

func TestValidateProxyDeclarationsRequiresAvailablePublicSchemes(t *testing.T) {
	testCases := []struct {
		name         string
		schemes      []protocol.HTTPPublicScheme
		httpEnabled  bool
		httpsEnabled bool
		wantCode     protocol.ProxyErrorCode
	}{
		{name: "missing defaults to HTTP", httpEnabled: true},
		{
			name:     "HTTP unavailable",
			schemes:  []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP},
			wantCode: protocol.ProxyErrorPublicSchemeUnavailable,
		},
		{
			name:        "HTTPS unavailable",
			schemes:     []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTPS},
			httpEnabled: true,
			wantCode:    protocol.ProxyErrorPublicSchemeUnavailable,
		},
		{
			name: "partial availability rejects complete declaration",
			schemes: []protocol.HTTPPublicScheme{
				protocol.HTTPPublicSchemeHTTP,
				protocol.HTTPPublicSchemeHTTPS,
			},
			httpEnabled: true,
			wantCode:    protocol.ProxyErrorPublicSchemeUnavailable,
		},
		{
			name: "both available",
			schemes: []protocol.HTTPPublicScheme{
				protocol.HTTPPublicSchemeHTTP,
				protocol.HTTPPublicSchemeHTTPS,
			},
			httpEnabled:  true,
			httpsEnabled: true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := validateProxyDeclarations(
				1,
				[]protocol.ProxyDeclaration{{
					Name: "web", Type: protocol.ProxyTypeHTTP,
					Domain: "app.example.com", PublicSchemes: testCase.schemes,
				}},
				testCase.httpEnabled,
				testCase.httpsEnabled,
			)
			if testCase.wantCode == "" {
				if result != nil {
					t.Fatalf("valid declaration was rejected: %+v", result.Error)
				}
				return
			}
			if result == nil || result.Error == nil || result.Error.Code != testCase.wantCode {
				t.Fatalf("result = %+v, want code %q", result, testCase.wantCode)
			}
		})
	}
}

func TestServeHTTPRejectsListenerOutsideBindingPublicSchemes(t *testing.T) {
	manager := &Registry{
		logger: logging.New("test"),
		httpDomains: map[string]*httpProxyBinding{
			"app.example.com": {
				declaration: protocol.ProxyDeclaration{
					Name: "web", Type: protocol.ProxyTypeHTTP,
					Domain:        "app.example.com",
					PublicSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTPS},
				},
			},
		},
	}
	request := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	request.Host = "app.example.com"
	request.TLS = nil
	response := httptest.NewRecorder()

	manager.ServeHTTP(response, request)

	if response.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMisdirectedRequest)
	}
}
