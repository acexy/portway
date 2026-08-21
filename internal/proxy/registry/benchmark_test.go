package registry

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/acexy/portway/internal/protocol"
)

func BenchmarkProxySync(b *testing.B) {
	benchmarkProxySync(b, 100)
}

func BenchmarkProxySyncMaximum(b *testing.B) {
	benchmarkProxySync(b, 128)
}

func benchmarkProxySync(b *testing.B, proxyCount int) {
	manager := newTestTCPProxyManager(b)
	manager.httpEnabled = true
	manager.Attach("benchmark-client", "benchmark-session", nil)
	declarations := make([]protocol.ProxyDeclaration, proxyCount)
	for index := range declarations {
		declarations[index] = protocol.ProxyDeclaration{
			Name:          fmt.Sprintf("proxy-%03d", index),
			Type:          protocol.ProxyTypeHTTP,
			Domain:        fmt.Sprintf("proxy-%03d.example.com", index),
			PublicSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP},
		}
	}
	request := protocol.SyncProxies{Revision: 1, Proxies: declarations}
	result := manager.Sync(
		"benchmark-client",
		"benchmark-session",
		"benchmark-request",
		request,
	)
	if result.Status != protocol.ProxySyncStatusApplied {
		b.Fatalf("initial proxy synchronization failed: %+v", result.Error)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		result = manager.Sync(
			"benchmark-client",
			"benchmark-session",
			"benchmark-request",
			request,
		)
		if result.Status != protocol.ProxySyncStatusApplied {
			b.Fatalf("proxy synchronization failed: %+v", result.Error)
		}
	}
}

func BenchmarkProxySyncParallel(b *testing.B) {
	const clientCount = 64
	manager := newTestTCPProxyManager(b)
	manager.httpEnabled = true
	clientIDs := make([]string, clientCount)
	sessionIDs := make([]string, clientCount)
	requests := make([]protocol.SyncProxies, clientCount)
	for index := range clientCount {
		clientIDs[index] = fmt.Sprintf("benchmark-client-%02d", index)
		sessionIDs[index] = fmt.Sprintf("benchmark-session-%02d", index)
		manager.Attach(clientIDs[index], sessionIDs[index], nil)
		requests[index] = protocol.SyncProxies{
			Revision: 1,
			Proxies: []protocol.ProxyDeclaration{{
				Name:          "web",
				Type:          protocol.ProxyTypeHTTP,
				Domain:        fmt.Sprintf("client-%02d.example.com", index),
				PublicSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP},
			}},
		}
		result := manager.Sync(
			clientIDs[index], sessionIDs[index], "benchmark-request", requests[index],
		)
		if result.Status != protocol.ProxySyncStatusApplied {
			b.Fatalf("initialize proxy synchronization %d: %+v", index, result.Error)
		}
	}

	var nextWorker atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(parallel *testing.PB) {
		worker := int(nextWorker.Add(1)-1) % clientCount
		for parallel.Next() {
			result := manager.Sync(
				clientIDs[worker],
				sessionIDs[worker],
				"benchmark-request",
				requests[worker],
			)
			if result.Status != protocol.ProxySyncStatusApplied {
				b.Fatalf("parallel proxy synchronization failed: %+v", result.Error)
			}
		}
	})
}
