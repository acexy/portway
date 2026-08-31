package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acexy/portway/internal/protocol"
)

func testForwardRule(cidr string, forwardType protocol.ForwardType, start uint16, end uint16) ForwardIPRule {
	rule := ForwardIPRule{IPRange: cidr}
	portRange := []PortRange{{Start: start, End: end}}
	if forwardType == protocol.ForwardTypeTCP {
		rule.TCP.PortRanges = portRange
	} else {
		rule.UDP.PortRanges = portRange
	}
	return rule
}

func TestValidateClientForwardConfiguration(t *testing.T) {
	configuration := DefaultClient()
	configuration.Authentication.Token = "client-forward-token-with-more-than-thirty-two-characters"
	configuration.Forwards = []ForwardConfig{{
		Name:   "database",
		Type:   protocol.ForwardTypeTCP,
		Listen: EndpointConfig{IP: "127.0.0.1", Port: 15432},
		Target: EndpointConfig{IP: "10.20.1.15", Port: 5432},
	}}
	if err := validateClient(configuration); err != nil {
		t.Fatalf("validate client Forward: %v", err)
	}

	configuration.Proxies = []ProxyConfig{{
		Name: "database", Type: protocol.ProxyTypeTCP,
		Local: EndpointConfig{IP: "127.0.0.1", Port: 22},
		Public: ProxyPublicConfig{Port: 22022},
	}}
	if err := validateClient(configuration); err == nil ||
		!strings.Contains(err.Error(), "duplicates a proxy name") {
		t.Fatalf("expected shared name rejection, got %v", err)
	}
}

func TestValidateForwardServerRules(t *testing.T) {
	rules := []ForwardIPRule{
		testForwardRule("10.0.0.0/8", protocol.ForwardTypeTCP, 5000, 5999),
	}
	if err := validateForwardServerConfig(ForwardServerConfig{Rules: rules}); err != nil {
		t.Fatalf("disabled Forward must allow validated preconfigured rules: %v", err)
	}
	if err := validateForwardServerConfig(ForwardServerConfig{Enabled: true}); err == nil {
		t.Fatal("enabled Forward without rules was accepted")
	}
	overlapping := append([]ForwardIPRule(nil), rules...)
	overlapping = append(
		overlapping,
		testForwardRule("10.20.0.0/16", protocol.ForwardTypeTCP, 5432, 5432),
	)
	if err := validateForwardServerConfig(ForwardServerConfig{
		Enabled: true,
		Rules:   overlapping,
	}); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("expected overlapping CIDR rejection, got %v", err)
	}
}

func TestLoadServerRequiresRulesWhenDisabledForwardSectionIsPresent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	writeTestConfiguration(t, path, "forwards:\n  enabled: false\n")
	if _, err := LoadServer(path, false); err == nil || !strings.Contains(err.Error(), "forwards.rules") {
		t.Fatalf("disabled configured Forward without rules was accepted: %v", err)
	}
}

func TestLoadServerValidatesForwardRulesAcrossAuthenticationModes(t *testing.T) {
	directory := t.TempDir()
	governedDirectory := filepath.Join(directory, "governed")
	managedDirectory := filepath.Join(directory, "managed")
	if err := os.Mkdir(governedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(managedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestConfiguration(t, filepath.Join(governedDirectory, "client.yaml"), `
authentication:
  client_id: governed-client
  token: governed-forward-token-with-more-than-thirty-two-characters
permissions:
  forwards:
    rules:
      - ip_range: 10.20.0.0/16
        tcp:
          port_ranges:
            - start: 5432
              end: 5432
`)
	writeTestConfiguration(t, filepath.Join(managedDirectory, "client.yaml"), `
authentication:
  client_id: managed-client
  token: managed-forward-token-with-more-than-thirty-two-characters
permissions:
  forwards:
    rules:
      - ip_range: 10.30.0.0/16
        udp:
          port_ranges:
            - start: 53
              end: 53
configuration:
  revision: 1
  proxies: []
  forwards:
    - name: dns
      type: udp
      listen:
        ip: 127.0.0.1
        port: 1053
      target:
        ip: 10.30.0.53
        port: 53
`)
	serverPath := filepath.Join(directory, "server.yaml")
	writeTestConfiguration(t, serverPath, `
forwards:
  enabled: true
  rules:
    - ip_range: 10.0.0.0/8
      tcp:
        port_ranges:
          - start: 5000
            end: 5999
      udp:
        port_ranges:
          - start: 53
            end: 53
authentication:
  governed_clients_path: governed
  managed_clients_path: managed
`)
	configuration, err := LoadServer(serverPath, false)
	if err != nil {
		t.Fatalf("load valid Forward configuration: %v", err)
	}
	if !configuration.Forwards.Enabled || len(configuration.ManagedClients["managed-client"].Configuration.Forwards) != 1 {
		t.Fatal("Forward configuration was not loaded")
	}
}

func TestLoadServerRejectsForwardPermissionOutsideGlobalRule(t *testing.T) {
	directory := t.TempDir()
	governedDirectory := filepath.Join(directory, "governed")
	if err := os.Mkdir(governedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestConfiguration(t, filepath.Join(governedDirectory, "client.yaml"), `
authentication:
  client_id: governed-client
  token: governed-forward-token-with-more-than-thirty-two-characters
permissions:
  forwards:
    rules:
      - ip_range: 10.20.0.0/16
        tcp:
          port_ranges:
            - start: 4900
              end: 5100
`)
	serverPath := filepath.Join(directory, "server.yaml")
	writeTestConfiguration(t, serverPath, `
forwards:
  enabled: true
  rules:
    - ip_range: 10.0.0.0/8
      tcp:
        port_ranges:
          - start: 5000
            end: 5999
authentication:
  governed_clients_path: governed
`)
	if _, err := LoadServer(serverPath, false); err == nil ||
		!strings.Contains(err.Error(), "not a subset") {
		t.Fatalf("expected Forward subset rejection, got %v", err)
	}
}

func TestLoadServerRejectsManagedForwardOutsideEffectiveRule(t *testing.T) {
	directory := t.TempDir()
	managedDirectory := filepath.Join(directory, "managed")
	if err := os.Mkdir(managedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestConfiguration(t, filepath.Join(managedDirectory, "client.yaml"), `
authentication:
  client_id: managed-client
  token: managed-forward-token-with-more-than-thirty-two-characters
configuration:
  revision: 1
  proxies: []
  forwards:
    - name: database
      type: tcp
      listen:
        ip: 127.0.0.1
        port: 15432
      target:
        ip: 10.20.1.15
        port: 5432
`)
	serverPath := filepath.Join(directory, "server.yaml")
	writeTestConfiguration(t, serverPath, `
forwards:
  enabled: true
  rules:
    - ip_range: 10.0.0.0/8
      tcp:
        port_ranges:
          - start: 22
            end: 22
authentication:
  managed_clients_path: managed
`)
	if _, err := LoadServer(serverPath, false); err == nil ||
		!strings.Contains(err.Error(), "target is not allowed") {
		t.Fatalf("expected Managed Forward target rejection, got %v", err)
	}
}

func TestDisabledForwardKeepsGovernedAndManagedConfigurationDormant(t *testing.T) {
	configuration := DefaultServer()
	configuration.Forwards = ForwardServerConfig{
		Configured: true,
		Enabled:    false,
		Rules: []ForwardIPRule{{
			IPRange: "127.0.0.1/32",
			TCP: ForwardPortPermission{PortRanges: []PortRange{{Start: 5432, End: 5432}}},
		}},
	}
	configuration.GovernedClients = map[string]GovernedClientConfig{
		"governed": {
			Authentication: ClientAuthenticationConfig{ClientID: "governed", Token: "governed-token-with-more-than-thirty-two-characters"},
			Permissions: GovernedPermissions{
				Proxies: GovernedProxyPermissions{Limits: DefaultProxyPermissionLimits()},
				Forwards: GovernedForwardPermissions{
					Rules: configuration.Forwards.Rules, Limits: DefaultForwardPermissionLimits(),
				},
			},
		},
	}
	configuration.ManagedClients = map[string]ManagedClientConfig{
		"managed": {
			Authentication: ClientAuthenticationConfig{ClientID: "managed", Token: "managed-token-with-more-than-thirty-two-characters"},
			Configuration: ManagedConfiguration{Revision: 1, Forwards: []ForwardConfig{{
				Name: "database", Type: protocol.ForwardTypeTCP,
				Listen: EndpointConfig{IP: "127.0.0.1", Port: 15432},
				Target: EndpointConfig{IP: "127.0.0.1", Port: 5432},
			}}},
		},
	}
	if err := validateForwardConfiguration(configuration); err != nil {
		t.Fatalf("disabled Forward rejected dormant client configuration: %v", err)
	}
}
