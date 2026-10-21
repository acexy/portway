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
	existing, err := manager.newHTTPBinding("client", "session", protocol.ProxyDeclaration{
		Name: "existing", Type: protocol.ProxyTypeHTTP, Domain: "existing.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer existing.close()
	// Observe the actual pool registrations without expanding the runtime API
	// solely for a cross-package rollback assertion. No pool mutations run here.
	poolCount := func() int { return reflect.ValueOf(manager.httpConnectionLimiter).Elem().FieldByName("pools").Len() }
	if poolCount() != 2 {
		t.Fatal("HTTP preparation did not register its transport")
	}
	result := manager.commitSync(syncCommitPreparation{
		clientID: "client", sessionID: "session", request: SyncRequest{Revision: 1},
		reusableEndpoints: map[uint16]*proxytcp.Endpoint{12345: {}},
		resources: &syncCandidateResources{
			nextHTTPProxies:     map[string]*httpProxyBinding{"web": binding, "existing": existing},
			existingHTTPProxies: map[string]*httpProxyBinding{"existing": existing},
		},
	}, nil)
	if result.Status != SyncStatusRejected {
		t.Fatal("changed port owner was accepted")
	}
	if poolCount() != 1 {
		t.Fatal("rollback retained a candidate transport or closed the reused transport")
	}
}

func TestEndpointPreparationFailureReleasesPreparedTCPListener(t *testing.T) {
	manager := newTestTCPProxyManager(t)
	manager.Attach("client", "session", nil)
	occupied, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	tcpAddress := reserveTCPAddress(t)
	result := manager.Sync("client", "session", "request", SyncRequest{
		Revision: 1,
		Proxies: []protocol.ProxyDeclaration{
			tcpProxyDeclaration("tcp", uint16(tcpAddress.Port)),
			udpProxyDeclaration("udp", uint16(occupied.LocalAddr().(*net.UDPAddr).Port)),
		},
	})
	if result.Status != SyncStatusRejected || result.Error == nil || result.Error.ProxyName != "udp" {
		t.Fatalf("expected UDP preparation rejection, got %+v", result)
	}
	listener, err := net.ListenTCP("tcp", tcpAddress)
	if err != nil {
		t.Fatalf("failed preparation retained the earlier TCP listener: %v", err)
	}
	listener.Close()
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
