package config

import (
	"encoding/json"
	"testing"

	"github.com/acexy/portway/internal/protocol"
)

func TestProxyDeclarationPreservesWireFieldsAndOwnsSchemes(t *testing.T) {
	configuration := ProxyConfig{
		Name: "web", Type: protocol.ProxyTypeHTTP,
		Local: EndpointConfig{IP: "127.0.0.1", Port: 8080},
		Public: ProxyPublicConfig{
			Domain:  "example.test",
			Schemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP, protocol.HTTPPublicSchemeHTTPS},
		},
	}
	declaration := ProxyDeclaration(configuration)
	encoded, err := json.Marshal(declaration)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"name":"web","type":"http","domain":"example.test","public_schemes":["http","https"]}` {
		t.Fatalf("declaration wire fields changed: %s", encoded)
	}
	configuration.Public.Schemes[0] = protocol.HTTPPublicSchemeHTTPS
	if declaration.PublicSchemes[0] != protocol.HTTPPublicSchemeHTTP {
		t.Fatal("declaration shares its scheme slice with the configuration")
	}
	for _, schemes := range [][]protocol.HTTPPublicScheme{nil, {}} {
		configuration.Public.Schemes = schemes
		declaration = ProxyDeclaration(configuration)
		if declaration.PublicSchemes != nil || !declaration.AllowsPublicScheme(protocol.HTTPPublicSchemeHTTP) ||
			declaration.AllowsPublicScheme(protocol.HTTPPublicSchemeHTTPS) {
			t.Fatal("empty public schemes changed the default HTTP-only declaration")
		}
	}
}

func TestForwardDeclarationExposesTargetWithoutLocalListener(t *testing.T) {
	declaration := ForwardDeclaration(ForwardConfig{
		Name: "database", Type: protocol.ForwardTypeTCP,
		Listen: EndpointConfig{IP: "127.0.0.1", Port: 15432},
		Target: EndpointConfig{IP: "10.0.0.2", Port: 5432},
	})
	encoded, err := json.Marshal(declaration)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"name":"database","type":"tcp","target_ip":"10.0.0.2","target_port":5432}` {
		t.Fatalf("declaration wire fields changed: %s", encoded)
	}
}
