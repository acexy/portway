package server

import (
	"testing"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
	proxyregistry "github.com/acexy/portway/internal/proxy/registry"
)

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
