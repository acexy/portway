package server

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/vnet"
)

func TestPeerRevocationDoesNotWaitForSlowSession(t *testing.T) {
	runtime := newServerVNetRuntime(context.Background(), logging.New("test"), config.DefaultServer().VirtualNetwork, nil)
	defer runtime.Close()
	slow, blocked := net.Pipe()
	defer blocked.Close()
	fast, reader := net.Pipe()
	defer reader.Close()
	runtime.mutex.Lock()
	runtime.sessions["slow"] = serverVNetSession{peerNotifier: runtime.newPeerNotifier(control.NewWriter(slow))}
	runtime.sessions["fast"] = serverVNetSession{peerNotifier: runtime.newPeerNotifier(control.NewWriter(fast))}
	key, first, second := peerPairKey("slow", "fast")
	runtime.peerPairs[key] = &serverVNetPeerPair{generation: 1, firstID: first, secondID: second, active: true}
	runtime.mutex.Unlock()
	done := make(chan struct{})
	go func() { runtime.revokeAllPeers("policy_changed"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("revocation waited for slow writer")
	}
	runtime.mutex.RLock()
	remaining := len(runtime.peerPairs)
	runtime.mutex.RUnlock()
	if remaining != 0 {
		t.Fatal("authority barrier retained pairs")
	}
	_ = reader.SetReadDeadline(time.Now().Add(time.Second))
	envelope, err := protocol.ReadControl(reader)
	if err != nil || envelope.Type != protocol.MessageVNetPeerRevoke {
		t.Fatalf("fast peer was not revoked: %v", err)
	}
}

func TestPeerQueueOverflowClosesAffectedSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local, remote := net.Pipe()
	defer remote.Close()
	notifier := &vnetPeerNotifier{context: ctx, cancel: cancel, writer: control.NewWriter(local), queue: make(chan vnetPeerNotice, 1)}
	if !notifier.enqueue(protocol.MessageVNetPeerRevoke, protocol.VNetPeerRevoke{}) {
		t.Fatal("first notice rejected")
	}
	if notifier.enqueue(protocol.MessageVNetPeerRevoke, protocol.VNetPeerRevoke{}) {
		t.Fatal("full queue accepted notice")
	}
	_ = remote.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := remote.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("overflow left old authority connected")
	}
	if ctx.Err() == nil {
		t.Fatal("overflow did not cancel notifier")
	}
}

func TestPeerFailedAndUnreadyPairsReleaseCapacity(t *testing.T) {
	now := time.Unix(100, 0)
	runtime := &serverVNetRuntime{sessions: make(map[string]serverVNetSession), peerPairs: make(map[string]*serverVNetPeerPair)}
	for index := range vnetMaximumNodePeers {
		key := string(rune(index))
		runtime.peerPairs[key] = &serverVNetPeerPair{retryAfter: now, generation: uint64(index + 1)}
	}
	runtime.expirePeerPairs(now)
	if len(runtime.peerPairs) != 0 {
		t.Fatal("expired backoff retained quota")
	}
	key, first, second := peerPairKey("first", "second")
	runtime.peerPairs[key] = &serverVNetPeerPair{generation: 100, firstID: first, secondID: second, expiresAt: now}
	runtime.expirePeerPairs(now)
	if runtime.peerPairs[key].retryAfter.IsZero() {
		t.Fatal("unready offer did not expire")
	}
	runtime.expirePeerPairs(now.Add(vnetPeerRetryDelay))
	if len(runtime.peerPairs) != 0 {
		t.Fatal("unready pair retained quota")
	}
	replacement := &serverVNetPeerPair{generation: 101, firstID: first, secondID: second, active: true}
	runtime.peerPairs[key] = replacement
	runtime.failPeerPair(first, second, 100, "late_failure")
	if !replacement.active {
		t.Fatal("old failure revoked new generation")
	}
}

func TestPeerOfferDoesNotBlockRelayCaller(t *testing.T) {
	configuration := config.DefaultServer().VirtualNetwork
	configuration.PacketChannels = 1
	configuration.Nodes = []config.VNetNodeConfig{{ClientID: "source", IP: "172.20.0.2"}, {ClientID: "target", IP: "172.20.0.3"}}
	runtime := newServerVNetRuntime(context.Background(), logging.New("test"), configuration, newBlockingVNetDevice())
	results := make(chan error, 2)
	started := 0
	defer func() {
		runtime.Close()
		for range started {
			<-results
		}
	}()
	for _, node := range configuration.Nodes {
		local, remote := net.Pipe()
		defer remote.Close()
		runtime.attach(node.ClientID, node.ClientID, 1, authentication.Context{}, control.NewWriter(local), true)
		runtime.mutex.Lock()
		session := runtime.sessions[node.ClientID]
		session.peerFingerprint = "test-fingerprint"
		runtime.sessions[node.ClientID] = session
		runtime.mutex.Unlock()
		spec := vnet.PoolSpec{ClientID: node.ClientID, SessionID: node.ClientID, VirtualIP: node.IP, PoolGeneration: 1, ChannelCount: 1, MTU: 1150, WriteTimeout: time.Second}
		offers, err := runtime.broker.Prepare(spec, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		channel, peer := net.Pipe()
		defer peer.Close()
		active := make(chan struct{})
		started++
		go func() {
			results <- runtime.broker.Bind(context.Background(), channel, protocol.BindVNetChannel{
				ClientID: spec.ClientID, SessionID: spec.SessionID, VirtualIP: spec.VirtualIP, PoolGeneration: 1, ChannelCount: 1, Ticket: offers[0].Ticket,
			}, authentication.Context{}, nil, func(*vnet.Pool) { close(active) })
		}()
		select {
		case <-active:
		case <-time.After(time.Second):
			t.Fatal("pool did not activate")
		}
	}
	done := make(chan struct{})
	go func() { runtime.offerPeer("source", "target"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("peer offer blocked relay caller")
	}
	runtime.mutex.RLock()
	count := len(runtime.peerPairs)
	runtime.mutex.RUnlock()
	if count != 1 {
		t.Fatal("test did not create a peer offer")
	}
}

func TestExpiredPeerReadyCannotBeatCleanupTick(t *testing.T) {
	key, first, second := peerPairKey("first", "second")
	pair := &serverVNetPeerPair{generation: 1, firstID: first, secondID: second, ready: map[string]bool{first: true}, expiresAt: time.Now().Add(-time.Second)}
	runtime := &serverVNetRuntime{sessions: map[string]serverVNetSession{second: {sessionID: "session"}}, peerPairs: map[string]*serverVNetPeerPair{key: pair}}
	if err := runtime.peerStatus(second, "session", protocol.VNetPeerStatus{PeerGeneration: 1, PeerClientID: first, State: protocol.VNetPeerStateReady}); err != nil {
		t.Fatal(err)
	}
	if pair.active || pair.retryAfter.IsZero() {
		t.Fatal("late ready activated expired offer")
	}
}
