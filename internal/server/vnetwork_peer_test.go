package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/vnet"
)

type pausedPeerNotice struct {
	started  chan struct{}
	resume   chan struct{}
	once     sync.Once
	mutex    sync.Mutex
	deadline time.Time
}

func (notice *pausedPeerNotice) Write(data []byte) (int, error) {
	notice.once.Do(func() { close(notice.started) })
	notice.mutex.Lock()
	deadline := notice.deadline
	notice.mutex.Unlock()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-notice.resume:
	case <-timer.C:
		return 0, context.DeadlineExceeded
	}
	return len(data), nil
}

func TestVNetReloadPublishesPolicyBeforePeerNotices(t *testing.T) {
	configuration := config.DefaultServer().VirtualNetwork
	configuration.Enabled = true
	configuration.Nodes = []config.VNetNodeConfig{
		{ClientID: "client-a", IP: "172.20.0.2"},
		{ClientID: "client-b", IP: "172.20.0.3", Ports: config.VNetPortPermissions{
			TCP: config.ForwardPortPermission{PortRanges: []config.PortRange{{Start: 8080, End: 8080}}},
		}},
	}
	runtime := newServerVNetRuntime(context.Background(), logging.New("test"), configuration, newBlockingVNetDevice())
	defer runtime.Close()
	notice := &pausedPeerNotice{started: make(chan struct{}), resume: make(chan struct{})}
	runtime.attach("client-a", "session-a", 1, authentication.Context{}, control.NewWriter(notice))
	runtime.attach("client-b", "session-b", 1, authentication.Context{}, control.NewWriter(discardConnection{}))
	key, first, second := peerPairKey("client-a", "client-b")
	runtime.peerPairs[key] = &serverVNetPeerPair{generation: 1, firstID: first, secondID: second, active: true}
	candidate := configuration
	candidate.Nodes = append([]config.VNetNodeConfig(nil), configuration.Nodes...)
	candidate.Nodes[1].Ports = config.VNetPortPermissions{}
	done := make(chan struct{})
	go func() { runtime.applyConfiguration(candidate, 2); close(done) }()
	defer func() { close(notice.resume); <-done }()
	select {
	case <-notice.started:
	case <-time.After(time.Second):
		t.Fatal("reload did not reach the peer notice")
	}
	_, err := runtime.router.AuthorizePeerFlow("client-a", vnet.Flow{
		Protocol: 6, SourceIP: netip.MustParseAddr("172.20.0.2"), SourcePort: 50000,
		DestinationIP: netip.MustParseAddr("172.20.0.3"), DestinationPort: 8080, TCPFlags: 2,
	}, time.Now())
	if !errors.Is(err, vnet.ErrFlowRejected) {
		t.Fatalf("blocked peer notice delayed policy revocation: %v", err)
	}
}

func TestPeerCandidateBudgetAndLiteralAddressValidation(t *testing.T) {
	invalid := []string{"example.test:7001", "127.0.0.1:7001", "0.0.0.0:7001", "224.0.0.1:7001", "192.168.0.1:0", "[::1]:7001"}
	if candidates := normalizePeerCandidates(invalid); len(candidates) != 0 {
		t.Fatalf("invalid host candidates were accepted: %v", candidates)
	}
	values := make([]string, 16)
	for index := range values {
		values[index] = fmt.Sprintf("192.168.0.%d:7001", index+1)
	}
	candidates := normalizePeerCandidates(values)
	if len(candidates) != 15 {
		t.Fatalf("host candidates did not reserve a public candidate slot: %d", len(candidates))
	}
	for _, candidate := range candidates {
		if _, err := netip.ParseAddrPort(candidate.Address); err != nil {
			t.Fatal(err)
		}
	}
	if len(normalizePeerCandidates([]string{values[0], values[0]})) != 1 {
		t.Fatal("duplicate candidates were retained")
	}
}

func TestLatePeerMessagesDoNotFailControlSession(t *testing.T) {
	runtime := &serverVNetRuntime{sessions: map[string]serverVNetSession{
		"client-a": {sessionID: "current"},
	}, peerPairs: make(map[string]*serverVNetPeerPair)}
	if err := runtime.peerStatus("client-a", "current", protocol.VNetPeerStatus{
		PeerGeneration: 1, PeerClientID: "client-b", State: protocol.VNetPeerStateReady,
	}); err != nil {
		t.Fatalf("late ready failed control session: %v", err)
	}
	if err := runtime.openPeerFlow("client-a", "current", protocol.VNetPeerFlowOpen{
		PeerGeneration: 1, PeerClientID: "client-b",
	}); err != nil {
		t.Fatalf("late flow registration failed control session: %v", err)
	}
	key, first, second := peerPairKey("client-a", "client-b")
	pair := &serverVNetPeerPair{generation: 1, firstID: first, secondID: second,
		retryAfter: time.Now().Add(time.Minute)}
	runtime.peerPairs[key] = pair
	if err := runtime.peerStatus("client-a", "current", protocol.VNetPeerStatus{
		PeerGeneration: 1, PeerClientID: "client-b", State: protocol.VNetPeerStateReady,
	}); err != nil || pair.active {
		t.Fatalf("late ready resurrected failed pair: %v", err)
	}
}

func (notice *pausedPeerNotice) SetWriteDeadline(deadline time.Time) error {
	notice.mutex.Lock()
	notice.deadline = deadline
	notice.mutex.Unlock()
	return nil
}
func (notice *pausedPeerNotice) Close() error { return nil }
