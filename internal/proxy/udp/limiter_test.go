package udp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
)

func TestLimiterEnforcesAssociationAndQueueBounds(t *testing.T) {
	configuration := config.DefaultUDPConfig()
	configuration.MaxAssociations = 1
	configuration.MaxAssociationsPerClient = 1
	configuration.MaxAssociationsPerProxy = 1
	configuration.MaxAssociationsPerSourceIP = 1
	configuration.MaxPendingAssociations = 1
	configuration.MaxPendingAssociationsPerClient = 1
	configuration.MaxPendingAssociationsPerProxy = 1
	configuration.MaxQueuedBytesPerAssociation = 65507
	configuration.MaxQueuedBytes = 65507
	limiter := NewLimiter(configuration)
	source := netip.MustParseAddr("192.0.2.10")
	lease, allowed := limiter.Acquire("client", "proxy", source, time.Now())
	if !allowed {
		t.Fatal("first association was rejected")
	}
	if _, allowed := limiter.Acquire("client", "proxy", source, time.Now()); allowed {
		t.Fatal("association limit was not enforced")
	}
	if !lease.ReserveQueue(65507) {
		t.Fatal("valid queue reservation was rejected")
	}
	if lease.ReserveQueue(1) {
		t.Fatal("queue byte limit was not enforced")
	}
	lease.ReleaseQueue(65507)
	lease.Close()
	if _, allowed := limiter.Acquire("client", "proxy", source, time.Now()); !allowed {
		t.Fatal("released association capacity was not reusable")
	}
}

func TestLimiterEnforcesAssociationCreationRate(t *testing.T) {
	configuration := config.DefaultUDPConfig()
	configuration.MaxNewAssociationsPerSecond = 1
	configuration.MaxNewAssociationsPerSecondPerClient = 1
	configuration.MaxNewAssociationsPerSecondPerProxy = 1
	limiter := NewLimiter(configuration)
	now := time.Now()
	first, allowed := limiter.Acquire(
		"client",
		"proxy",
		netip.MustParseAddr("192.0.2.10"),
		now,
	)
	if !allowed {
		t.Fatal("first association was rejected")
	}
	first.Close()
	if _, allowed := limiter.Acquire(
		"client",
		"proxy",
		netip.MustParseAddr("192.0.2.11"),
		now,
	); allowed {
		t.Fatal("association creation rate was not enforced")
	}
}
