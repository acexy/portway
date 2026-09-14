package vnet

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestNetworkMigrationUpdatesAddressAndRollsBackFailures(t *testing.T) {
	manifest := ownershipManifest{Role: NetworkRoleClient, CIDR: "172.20.0.0/16",
		LocalIP: "172.20.0.2", ServerIP: "172.20.0.1", MTU: 1280, InstallationID: "installation"}
	spec := NetworkSpec{Role: NetworkRoleClient, CIDR: "172.21.0.0/16",
		LocalIP: "172.21.0.2", ServerIP: "172.21.0.1", MTU: 1280}
	for _, test := range []struct {
		name string
		fail string
		want []string
	}{
		{"success", "", []string{"remove old", "add new", "identity new", "store new"}},
		{"address failure", "add new", []string{"remove old", "add new", "add old", "identity old", "store old"}},
		{"manifest failure", "store new", []string{"remove old", "add new", "identity new", "store new", "remove new", "add old", "identity old", "store old"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			failure := errors.New("injected installation failure")
			record := func(action string, value NetworkSpec) error {
				generation := "new"
				if value.LocalIP == manifest.LocalIP {
					generation = "old"
				}
				call := action + " " + generation
				calls = append(calls, call)
				if call == test.fail {
					return failure
				}
				return nil
			}
			operations := networkMigrationOperations{
				removeAddress: func(_ context.Context, value NetworkSpec) error { return record("remove", value) },
				addAddress:    func(_ context.Context, value NetworkSpec) error { return record("add", value) },
				setIdentity: func(_ context.Context, value NetworkSpec, identifier string) error {
					if identifier != manifest.InstallationID {
						t.Fatal("migration replaced the installation identity")
					}
					return record("identity", value)
				},
				store: func(_ context.Context, value NetworkSpec, _ string) error { return record("store", value) },
			}
			err := migrateNetworkInstallation(context.Background(), manifest, spec, operations)
			if errors.Is(err, failure) != (test.fail != "") || !reflect.DeepEqual(calls, test.want) {
				t.Fatalf("migration calls = %v, error = %v; want %v", calls, err, test.want)
			}
		})
	}
}

func TestNetworkManifestComparisonDetectsConfigurationChanges(t *testing.T) {
	manifest := ownershipManifest{Role: NetworkRoleClient, CIDR: "172.20.0.0/16", LocalIP: "172.20.0.2",
		ServerIP: "172.20.0.1", MTU: 1280}
	spec := NetworkSpec{Role: manifest.Role, CIDR: manifest.CIDR, LocalIP: manifest.LocalIP,
		ServerIP: manifest.ServerIP, MTU: manifest.MTU}
	if !networkSpecMatchesManifest(spec, manifest) {
		t.Fatal("identical configuration requires migration")
	}
	for _, change := range []func(*NetworkSpec){
		func(value *NetworkSpec) { value.CIDR = "172.20.0.0/24" },
		func(value *NetworkSpec) { value.LocalIP = "172.20.0.3" },
		func(value *NetworkSpec) { value.ServerIP = "172.20.0.10" },
		func(value *NetworkSpec) { value.MTU = 1400 },
	} {
		candidate := spec
		change(&candidate)
		if networkSpecMatchesManifest(candidate, manifest) {
			t.Fatal("configuration change was ignored")
		}
	}
}
