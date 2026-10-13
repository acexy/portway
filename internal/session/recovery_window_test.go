package session

import (
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/protocol"
)

func TestRecoveryInitializationKeepsOriginalExpiry(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		name := "initializing"
		if disconnect {
			name = "failed_initialization"
		}
		t.Run(name, func(t *testing.T) {
			registry := NewRegistry()
			local, peer := net.Pipe()
			defer local.Close()
			defer peer.Close()
			start := time.Unix(1000, 0)
			registry.Register("client", "", "old", local, start)
			if !registry.Activate("client", "old", start) {
				t.Fatal("activation failed")
			}
			registry.Disconnect("client", "old", start)
			resumed, _, _, err := registry.Register("client", "old", "new", local, start.Add(30*time.Second))
			if !resumed || err != nil {
				t.Fatalf("resume failed: %v", err)
			}
			if disconnect {
				registry.Disconnect("client", "new", start.Add(50*time.Second))
			}
			deadline := start.Add(RecoveryWindow)
			if registry.Activate("client", "new", deadline) {
				t.Fatal("expired recovery activated before sweep")
			}
			if accepted, _ := registry.Heartbeat("client", "new", 1, deadline); accepted {
				t.Fatal("expired session accepted heartbeat")
			}
			_, _, _, err = registry.Register("client", "new", "third", local, deadline)
			if err == nil || err.Code != protocol.SessionErrorSessionExpired {
				t.Fatalf("expired session resumed: %v", err)
			}
			_, expired := registry.Sweep(deadline, 20*time.Second)
			if len(expired) != 1 || expired[0].SessionID != "new" {
				t.Fatalf("original deadline was extended: %v", expired)
			}
		})
	}
}

func TestSuccessfulRecoveryStartsNewSuspensionWindow(t *testing.T) {
	registry := NewRegistry()
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	start := time.Unix(1000, 0)
	registry.Register("client", "", "old", local, start)
	registry.Activate("client", "old", start)
	registry.Disconnect("client", "old", start)
	registry.Register("client", "old", "new", local, start.Add(30*time.Second))
	if !registry.Activate("client", "new", start.Add(40*time.Second)) {
		t.Fatal("recovery activation failed")
	}
	registry.Disconnect("client", "new", start.Add(50*time.Second))
	_, expired := registry.Sweep(start.Add(RecoveryWindow), 20*time.Second)
	if len(expired) != 0 {
		t.Fatal("successful recovery retained old deadline")
	}
	_, expired = registry.Sweep(start.Add(50*time.Second+RecoveryWindow), 20*time.Second)
	if len(expired) != 1 {
		t.Fatal("new suspension did not expire")
	}
}

func TestRecoveryRetainsKnownIdentityAcrossLostHellos(t *testing.T) {
	registry := NewRegistry()
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	start := time.Unix(1000, 0)
	registry.Register("client", "", "known", local, start)
	registry.Activate("client", "known", start)
	registry.Disconnect("client", "known", start)
	for index, next := range []string{"lost-first", "lost-second", "received"} {
		now := start.Add(time.Duration(index+1) * time.Second)
		resumed, _, _, err := registry.Register("client", "known", next, local, now)
		if err != nil || !resumed {
			t.Fatalf("lost Hello made known identity unusable: %v", err)
		}
		if next != "received" {
			registry.Disconnect("client", next, now)
		}
	}
	if !registry.Activate("client", "received", start.Add(4*time.Second)) {
		t.Fatal("final activation failed")
	}
	registry.Disconnect("client", "received", start.Add(5*time.Second))
	_, _, _, err := registry.Register("client", "known", "replay", local, start.Add(6*time.Second))
	if err == nil || err.Code != protocol.SessionErrorResumeSessionMismatch {
		t.Fatalf("activation retained obsolete identity: %v", err)
	}
}
