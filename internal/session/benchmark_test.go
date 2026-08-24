package session

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func BenchmarkSessionLifecycle(b *testing.B) {
	registry := NewRegistryWithLimit(256)
	now := time.Unix(100, 0)
	b.ReportAllocs()
	for b.Loop() {
		_, created, _, sessionError := registry.Register(
			"benchmark-client",
			"",
			"session-one",
			nil,
			now,
		)
		if !created || sessionError != nil {
			b.Fatalf("register session: created=%t error=%v", created, sessionError)
		}
		if !registry.Activate("benchmark-client", "session-one", now) {
			b.Fatal("activate initial session")
		}
		accepted, reactivated := registry.Heartbeat(
			"benchmark-client",
			"session-one",
			1,
			now.Add(time.Second),
		)
		if !accepted || reactivated {
			b.Fatal("accept active session heartbeat")
		}
		registry.Disconnect("benchmark-client", "session-one", now.Add(2*time.Second))
		resumed, _, _, sessionError := registry.Register(
			"benchmark-client",
			"session-one",
			"session-two",
			nil,
			now.Add(3*time.Second),
		)
		if !resumed || sessionError != nil {
			b.Fatalf("resume session: resumed=%t error=%v", resumed, sessionError)
		}
		if !registry.Activate("benchmark-client", "session-two", now.Add(3*time.Second)) {
			b.Fatal("activate resumed session")
		}
		registry.Remove("benchmark-client", "session-two")
	}
}

func BenchmarkSessionHeartbeatParallel(b *testing.B) {
	const clientCount = 256
	registry := NewRegistryWithLimit(clientCount)
	now := time.Unix(100, 0)
	clientIDs := make([]string, clientCount)
	sessionIDs := make([]string, clientCount)
	for index := range clientCount {
		clientIDs[index] = fmt.Sprintf("benchmark-client-%03d", index)
		sessionIDs[index] = fmt.Sprintf("benchmark-session-%03d", index)
		_, created, _, sessionError := registry.Register(
			clientIDs[index], "", sessionIDs[index], nil, now,
		)
		if !created || sessionError != nil ||
			!registry.Activate(clientIDs[index], sessionIDs[index], now) {
			b.Fatalf("initialize session %d: created=%t error=%v", index, created, sessionError)
		}
	}

	var nextWorker atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(parallel *testing.PB) {
		worker := int(nextWorker.Add(1)-1) % clientCount
		sequence := uint64(1)
		for parallel.Next() {
			accepted, _ := registry.Heartbeat(
				clientIDs[worker],
				sessionIDs[worker],
				sequence,
				now,
			)
			if !accepted {
				b.Fatal("parallel heartbeat rejected")
			}
			sequence++
		}
	})
}
