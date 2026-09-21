package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"testing"

	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
)

func TestVNetReconnectRetainsSocketAndDisableReleasesIt(t *testing.T) {
	reservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.LocalAddr().(*net.UDPAddr).Port
	address := reservation.LocalAddr().(*net.UDPAddr)
	reservation.Close()
	var owner clientVNetPeerRuntime
	defer owner.close()
	assignment := lifecycleVNetAssignment()
	assignment.PeerRegistrationTicket = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	newManager := func(session string) *clientVNetManager {
		local, remote := net.Pipe()
		t.Cleanup(func() { local.Close(); remote.Close() })
		// Status writes are drained without involving a real server or system TUN.
		go func() {
			for {
				if _, err := protocol.ReadControl(remote); err != nil {
					return
				}
			}
		}()
		manager := newClientVNetManager(context.Background(), logging.New("test"), "managed-a", session, control.NewWriter(local), nil, fmt.Sprintf("127.0.0.1:%d", port-1))
		manager.peerRuntime = &owner
		return manager
	}
	first := newManager("first-session")
	defer first.close()
	if err := first.preparePeerEndpoint(assignment); err != nil {
		t.Fatal(err)
	}
	original := owner.socket
	fingerprint := first.peerEndpoint.Fingerprint()
	first.close()
	if owner.socket != original || !original.Healthy() {
		t.Fatal("session close destroyed process socket")
	}
	if probe, err := net.ListenUDP("udp4", address); err == nil {
		probe.Close()
		t.Fatal("port was released during reconnect")
	}
	second := newManager("second-session")
	defer second.close()
	if err := second.preparePeerEndpoint(assignment); err != nil {
		t.Fatalf("reconnect rebound occupied port: %v", err)
	}
	if owner.socket != original || second.peerEndpoint.Fingerprint() == fingerprint {
		t.Fatal("socket not reused with fresh identity")
	}
	second.assignment = assignment
	previousFingerprint := second.peerEndpoint.Fingerprint()
	assignment.ClientIP, assignment.MTU = "172.20.0.4", 1100
	if err := second.preparePeerEndpoint(assignment); err != nil {
		t.Fatal(err)
	}
	if owner.socket != original || second.peerEndpoint.Fingerprint() == previousFingerprint {
		t.Fatal("address migration did not replace only the session endpoint")
	}
	first.close()
	if !original.Healthy() {
		t.Fatal("late old session close affected socket")
	}
	second.assignment = assignment
	if err := second.deactivate(protocol.VNetDeactivate{PoolGeneration: assignment.PoolGeneration, Reason: protocol.VNetDeactivateDisabled}); err != nil {
		t.Fatal(err)
	}
	if owner.socket != nil {
		t.Fatal("disable retained process socket")
	}
	probe, err := net.ListenUDP("udp4", address)
	if err != nil {
		t.Fatalf("disable did not release port: %v", err)
	}
	probe.Close()
	// Re-enabling is permitted to bind again after an explicit disable.
	if err := second.preparePeerEndpoint(assignment); err != nil {
		t.Fatal(err)
	}
	if owner.socket == original {
		t.Fatal("re-enable reused closed socket")
	}
	second.close()
	owner.close()
	probe, err = net.ListenUDP("udp4", address)
	if err != nil {
		t.Fatalf("process close did not release port: %v", err)
	}
	probe.Close()
}

func TestVNetPeerRuntimeRebuildsFailedBinding(t *testing.T) {
	var owner clientVNetPeerRuntime
	defer owner.close()
	first, err := owner.newEndpoint(context.Background(), "127.0.0.1:0", "client-a", "first", "172.20.0.2", 1150, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	original := owner.socket
	// A failed transport is discarded, unlike an ordinary session disconnect.
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := owner.newEndpoint(context.Background(), "127.0.0.1:0", "client-a", "second", "172.20.0.2", 1150, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if owner.socket == original || !owner.socket.Healthy() {
		t.Fatal("closed binding was reused")
	}
	first.Close()
	if !owner.socket.Healthy() {
		t.Fatal("late close invalidated replacement binding")
	}
}
