package protocol

import "testing"

func TestEmptyHTTPPublicSchemesDefaultToHTTP(t *testing.T) {
	declaration := ProxyDeclaration{Type: ProxyTypeHTTP}
	if !declaration.AllowsPublicScheme(HTTPPublicSchemeHTTP) {
		t.Fatal("empty public schemes did not allow the default HTTP listener")
	}
	if declaration.AllowsPublicScheme(HTTPPublicSchemeHTTPS) {
		t.Fatal("empty public schemes unexpectedly allowed HTTPS")
	}
}
