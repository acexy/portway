package udp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
)

func BenchmarkAssociationLifecycle(b *testing.B) {
	configuration := config.DefaultUDPConfig()
	configuration.MaxAssociations = 4096
	configuration.MaxNewAssociationsPerSecond = 10000
	configuration.MaxNewAssociationsPerSecondPerClient = 2000
	configuration.MaxNewAssociationsPerSecondPerProxy = 1000
	limiter := NewLimiter(configuration)
	source := netip.MustParseAddr("192.0.2.1")
	now := time.Unix(100, 0)
	b.ReportAllocs()
	for b.Loop() {
		lease, accepted := limiter.Acquire("benchmark-client", "benchmark-proxy", source, now)
		if !accepted {
			now = now.Add(time.Second)
			lease, accepted = limiter.Acquire("benchmark-client", "benchmark-proxy", source, now)
		}
		if !accepted {
			b.Fatal("association was unexpectedly rejected")
		}
		lease.Activate()
		lease.Close()
	}
}
