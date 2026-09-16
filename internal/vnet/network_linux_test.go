//go:build linux

package vnet

import "testing"

func TestLinuxOwnershipRequiresInterfaceBinding(t *testing.T) {
	manifest := ownershipManifest{PlatformInterface: LogicalInterfaceName, InstallationID: "installation"}
	for _, test := range []struct {
		data  string
		valid bool
	}{
		{`[{"ifname":"portway0","ifalias":"portway:installation","linkinfo":{"info_kind":"tun","info_data":{"type":"tun"}}}]`, true},
		{`[{"ifname":"portway0","ifalias":"portway:installation","linkinfo":{"info_kind":"tun","info_data":{"type":"tap"}}}]`, false},
		{`[{"ifname":"portway0","linkinfo":{"info_kind":"tun","info_data":{"type":"tun"}}}]`, false},
		{`[{"ifname":"portway0","ifalias":"portway:other","linkinfo":{"info_kind":"tun","info_data":{"type":"tun"}}}]`, false},
		{`[{"ifname":"portway0","ifalias":"portway:installation","linkinfo":{"info_kind":"dummy"}}]`, false},
	} {
		if linuxIdentityMatches([]byte(test.data), manifest) != test.valid {
			t.Fatalf("unexpected ownership result for %s", test.data)
		}
	}
}

func TestLinuxRoutesIncludeHostAndNonMainTables(t *testing.T) {
	routes, err := parseLinuxNetworkRoutes([]byte(`[{"dst":"default"},{"dst":"172.20.1.2","table":"local"},{"dst":"172.16.0.0/12","table":100}]`))
	if err != nil || len(routes) != 2 || routes[0].Bits() != 32 || routes[1].Bits() != 12 {
		t.Fatalf("routes = %v, error = %v", routes, err)
	}
	if _, err := parseLinuxNetworkRoutes([]byte(`[{"dst":"invalid"}]`)); err == nil {
		t.Fatal("invalid route snapshot accepted")
	}
}

func TestLinuxLegacyIdentityCanBeInstalledWithoutAcceptingForeignAlias(t *testing.T) {
	manifest := ownershipManifest{PlatformInterface: LogicalInterfaceName, InstallationID: "installation"}
	legacy := []byte(`[{"ifname":"portway0","linkinfo":{"info_kind":"tun","info_data":{"type":"tun"}}}]`)
	if !linuxIdentityCanBeInstalled(legacy, manifest) || linuxIdentityMatches(legacy, manifest) {
		t.Fatal("legacy installation must be eligible for automatic binding before opening")
	}
	foreign := []byte(`[{"ifname":"portway0","ifalias":"another-owner","linkinfo":{"info_kind":"tun","info_data":{"type":"tun"}}}]`)
	if linuxIdentityCanBeInstalled(foreign, manifest) {
		t.Fatal("foreign alias was eligible for automatic replacement")
	}
}

func TestLinuxMigrationExcludesAllRoutesOnReplacedInterface(t *testing.T) {
	data := []byte(`[{"dst":"172.20.0.0/16","dev":"portway0","protocol":"kernel"},{"dst":"172.21.0.0/16","dev":"other0","protocol":"kernel"}]`)
	routes, err := parseLinuxNetworkRoutesExcluding(data, LogicalInterfaceName)
	if err != nil || len(routes) != 1 || routes[0].String() != "172.21.0.0/16" {
		t.Fatalf("migration routes = %v, error = %v", routes, err)
	}
	routes, err = parseLinuxNetworkRoutesExcluding(
		[]byte(`[{"dst":"172.20.0.0/16","dev":"portway0","protocol":"static"}]`),
		LogicalInterfaceName,
	)
	if err != nil || len(routes) != 0 {
		t.Fatalf("replaced interface routes = %v, error = %v", routes, err)
	}
}
