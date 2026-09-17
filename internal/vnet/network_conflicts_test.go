package vnet

import (
	"errors"
	"net/netip"
	"testing"
)

func TestNetworkConflictBoundaries(t *testing.T) {
	candidate := netip.MustParsePrefix("172.20.0.0/16")
	for _, test := range []struct {
		name     string
		address  string
		route    string
		conflict bool
	}{
		{"default route", "192.168.1.2/24", "0.0.0.0/0", false},
		{"address overlap", "172.20.1.2/24", "0.0.0.0/0", true},
		{"containing route", "192.168.1.2/24", "172.16.0.0/12", true},
		{"contained route", "192.168.1.2/24", "172.20.1.0/24", true},
		{"host route", "192.168.1.2/24", "172.20.1.2/32", true},
		{"adjacent route", "192.168.1.2/24", "172.21.0.0/16", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateNetworkConflicts(candidate,
				[]netip.Prefix{netip.MustParsePrefix(test.address)},
				[]netip.Prefix{netip.MustParsePrefix(test.route)})
			if errors.Is(err, ErrForeignResource) != test.conflict {
				t.Fatalf("conflict = %v, want %v", err, test.conflict)
			}
		})
	}
}
