package registry

import (
	"net"
	"reflect"
	"testing"

	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
)

func TestPortOwnershipFailureReleasesHTTPPreparation(t *testing.T) {
	manager := newTestTCPProxyManager(t)
	manager.Attach("client", "session", nil)
	binding, err := manager.newHTTPBinding("client", "session", protocol.ProxyDeclaration{
		Name: "web", Type: protocol.ProxyTypeHTTP, Domain: "example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Observe the actual pool registrations without expanding the runtime API
	// solely for a cross-package rollback assertion. No pool mutations run here.
	poolCount := func() int { return reflect.ValueOf(manager.httpConnectionLimiter).Elem().FieldByName("pools").Len() }
	if poolCount() != 1 {
		t.Fatal("HTTP preparation did not register its transport")
	}
	result := manager.commitSync(syncCommitPreparation{
		clientID: "client", sessionID: "session", request: SyncRequest{Revision: 1},
		reusableEndpoints: map[uint16]*proxytcp.Endpoint{12345: {}},
		nextHTTPProxies:   map[string]*httpProxyBinding{"web": binding},
	}, nil)
	if result.Status != SyncStatusRejected {
		t.Fatal("changed port owner was accepted")
	}
	if poolCount() != 0 {
		t.Fatal("rejected candidate retained an HTTP transport registration")
	}
}

func TestCoordinatedSyncPreparesBeforePublicationAndRollsBack(t *testing.T) {
	manager := newTestTCPProxyManager(t)
	manager.Attach("client", "session", nil)
	port := uint16(reserveTCPAddress(t).Port)
	request := SyncRequest{Revision: 1, Proxies: []protocol.ProxyDeclaration{tcpProxyDeclaration("tcp", port)}}
	called := false
	result := manager.SyncCoordinated("client", "session", "request", request, func(publish func() bool) bool {
		called = true
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)})
		if err == nil {
			listener.Close()
			t.Error("listener preparation ran inside publication callback")
		}
		return false
	})
	if !called || result.Status != SyncStatusRejected {
		t.Fatal("companion rejection was ignored")
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)})
	if err != nil {
		t.Fatalf("rollback retained listener: %v", err)
	}
	listener.Close()
	result = manager.SyncCoordinated("client", "session", "request", request, func(publish func() bool) bool { return publish() })
	if result.Status != SyncStatusApplied {
		t.Fatalf("rollback poisoned the next transaction: %+v", result.Error)
	}
}
