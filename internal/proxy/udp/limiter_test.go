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

func TestLimiterDoesNotConsumeGlobalRateWhenClientRateRejects(t *testing.T) {
	configuration := config.DefaultUDPConfig()
	configuration.MaxNewAssociationsPerSecond = 2
	configuration.MaxNewAssociationsPerSecondPerClient = 1
	configuration.MaxNewAssociationsPerSecondPerProxy = 2
	limiter := NewLimiter(configuration)
	now := time.Now()

	first, allowed := limiter.Acquire(
		"client-one", "proxy", netip.MustParseAddr("192.0.2.10"), now,
	)
	if !allowed {
		t.Fatal("first association was rejected")
	}
	defer first.Close()
	if _, allowed := limiter.Acquire(
		"client-one", "proxy", netip.MustParseAddr("192.0.2.11"), now,
	); allowed {
		t.Fatal("per-client rate limit was not enforced")
	}
	second, allowed := limiter.Acquire(
		"client-two", "proxy", netip.MustParseAddr("192.0.2.12"), now,
	)
	if !allowed {
		t.Fatal("rejected client consumed the remaining global rate capacity")
	}
	second.Close()
}

func TestLimiterSoakReleasesAllAssociationAndQueueAccounting(t *testing.T) {
	configuration := config.DefaultUDPConfig()
	configuration.MaxNewAssociationsPerSecond = 10000
	configuration.MaxNewAssociationsPerSecondPerClient = 2000
	configuration.MaxNewAssociationsPerSecondPerProxy = 1000
	limiter := NewLimiter(configuration)
	now := time.Unix(100, 0)
	for index := 0; index < 5000; index++ {
		lease, accepted := limiter.Acquire(
			"soak-client",
			"soak-proxy",
			netip.MustParseAddr("192.0.2.1"),
			now.Add(time.Duration(index/500)*time.Second),
		)
		if !accepted {
			t.Fatalf("association %d was unexpectedly rejected", index)
		}
		lease.Activate()
		if !lease.ReserveQueue(1024) {
			t.Fatalf("association %d could not reserve queue bytes", index)
		}
		lease.Close()
	}
	stats := limiter.SnapshotStats()
	if stats.Associations != 0 || stats.PendingAssociations != 0 || stats.QueuedBytes != 0 {
		t.Fatalf("UDP accounting leaked after soak: %+v", stats)
	}
}
