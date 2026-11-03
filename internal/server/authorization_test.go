package server

import (
	"testing"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
	proxyregistry "github.com/acexy/portway/internal/proxy/registry"
)

func TestGovernedForwardLimitsAcceptBoundaryAndRejectMissingClient(t *testing.T) {
	declarations := []protocol.ForwardDeclaration{{Type: protocol.ForwardTypeTCP}, {Type: protocol.ForwardTypeUDP}}
	for _, limits := range []config.ForwardPermissionLimits{{}, {MaxTotal: 2, MaxTCP: 1, MaxUDP: 1}} {
		service := &Service{configuration: newConfigurationManager(config.ServerConfig{
			GovernedClients: map[string]config.GovernedClientConfig{"client": {Permissions: config.GovernedPermissions{
				Forwards: config.GovernedForwardPermissions{Limits: limits},
			}}},
		})}
		if rejection := service.validateGovernedForwardLimits("client", declarations); rejection != nil {
			t.Fatalf("valid boundary rejected: %+v", rejection)
		}
		if rejection := service.validateGovernedForwardLimits("missing", declarations); rejection == nil || rejection.Code != protocol.ConfigurationErrorCode(protocol.ForwardErrorInvalidRequest) {
			t.Fatalf("missing client accepted: %+v", rejection)
		}
	}
}

func TestValidateGovernedProxiesAppliesTypePortAndDomainPermissions(t *testing.T) {
	service := &Service{
		configuration: newConfigurationManager(config.ServerConfig{
			GovernedClients: map[string]config.GovernedClientConfig{
				"customer-a": {
					Authentication: config.ClientAuthenticationConfig{ClientID: "customer-a"},
					Permissions: config.GovernedPermissions{
						Proxies: config.GovernedProxyPermissions{
							TCP: &config.ProxyPermission{
								PortRanges: []config.PortRange{{Start: 20000, End: 20999}},
							},
							HTTP: &config.HTTPPermission{
								PublicSchemes: []protocol.HTTPPublicScheme{
									protocol.HTTPPublicSchemeHTTPS,
								},
								Domains: []string{"*.customer-a.example.com"},
							},
							Limits: config.ProxyPermissionLimits{MaxTotal: 2},
						},
					},
				},
			},
		}),
	}
	allowed := proxyregistry.SyncRequest{
		Revision: 1,
		Proxies: []protocol.ProxyDeclaration{
			{Name: "ssh", Type: protocol.ProxyTypeTCP, RemotePort: 20022},
			{
				Name: "web", Type: protocol.ProxyTypeHTTP,
				Domain:        "app.customer-a.example.com",
				PublicSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTPS},
			},
		},
	}
	if result := service.validateGovernedProxies("customer-a", allowed); result != nil {
		t.Fatalf("allowed governed configuration was rejected: %+v", result)
	}

	disallowed := allowed
	disallowed.Proxies = append([]protocol.ProxyDeclaration(nil), allowed.Proxies...)
	disallowed.Proxies[0].RemotePort = 22022
	result := service.validateGovernedProxies("customer-a", disallowed)
	if result == nil || result.Error == nil ||
		result.Error.Code != proxyregistry.ErrorRemotePortNotAllowed {
		t.Fatalf("expected remote port rejection, got %+v", result)
	}

	disallowed = allowed
	disallowed.Proxies = append([]protocol.ProxyDeclaration(nil), allowed.Proxies...)
	disallowed.Proxies[1].PublicSchemes = []protocol.HTTPPublicScheme{
		protocol.HTTPPublicSchemeHTTP,
	}
	result = service.validateGovernedProxies("customer-a", disallowed)
	if result == nil || result.Error == nil ||
		result.Error.Code != proxyregistry.ErrorPublicSchemeNotAllowed {
		t.Fatalf("expected public scheme rejection, got %+v", result)
	}
}
