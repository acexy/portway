package registry

import (
	"context"
	"net"
	"testing"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/protocol"
)

func TestTCPProxySyncReusesEndpointWhenProxyIsRenamed(t *testing.T) {
	t.Parallel()

	manager := newTestTCPProxyManager(t)
	port := uint16(reserveTCPAddress(t).Port)
	manager.Attach("client-one", "session-one", nil)

	first := manager.Sync(
		"client-one",
		"session-one",
		"request-one",
		protocol.SyncProxies{
			Revision: 1,
			Proxies: []protocol.ProxyDeclaration{
				tcpProxyDeclaration("old-name", port),
			},
		},
	)
	if first.Status != protocol.ProxySyncStatusApplied {
		t.Fatalf("initial proxy synchronization failed: %+v", first.Error)
	}
	originalEndpoint := manager.endpoints[port]

	second := manager.Sync(
		"client-one",
		"session-one",
		"request-two",
		protocol.SyncProxies{
			Revision: 2,
			Proxies: []protocol.ProxyDeclaration{
				tcpProxyDeclaration("new-name", port),
			},
		},
	)
	if second.Status != protocol.ProxySyncStatusApplied {
		t.Fatalf("proxy rename failed: %+v", second.Error)
	}
	if manager.endpoints[port] != originalEndpoint {
		t.Fatal("proxy rename replaced the endpoint listener")
	}
	state := manager.clients["client-one"]
	if state.tcpProxies["old-name"] != nil {
		t.Fatal("old proxy binding was retained after rename")
	}
	if state.tcpProxies["new-name"] == nil ||
		manager.endpointBindings[port] != state.tcpProxies["new-name"] {
		t.Fatal("renamed proxy was not atomically bound to the existing endpoint")
	}
}

func TestTCPProxySyncSwapsExistingEndpoints(t *testing.T) {
	t.Parallel()

	manager := newTestTCPProxyManager(t)
	firstPort := uint16(reserveTCPAddress(t).Port)
	secondPort := uint16(reserveTCPAddress(t).Port)
	manager.Attach("client-one", "session-one", nil)

	initial := manager.Sync(
		"client-one",
		"session-one",
		"request-one",
		protocol.SyncProxies{
			Revision: 1,
			Proxies: []protocol.ProxyDeclaration{
				tcpProxyDeclaration("first", firstPort),
				tcpProxyDeclaration("second", secondPort),
			},
		},
	)
	if initial.Status != protocol.ProxySyncStatusApplied {
		t.Fatalf("initial proxy synchronization failed: %+v", initial.Error)
	}
	firstEndpoint := manager.endpoints[firstPort]
	secondEndpoint := manager.endpoints[secondPort]

	swapped := manager.Sync(
		"client-one",
		"session-one",
		"request-two",
		protocol.SyncProxies{
			Revision: 2,
			Proxies: []protocol.ProxyDeclaration{
				tcpProxyDeclaration("first", secondPort),
				tcpProxyDeclaration("second", firstPort),
			},
		},
	)
	if swapped.Status != protocol.ProxySyncStatusApplied {
		t.Fatalf("proxy endpoint swap failed: %+v", swapped.Error)
	}
	if manager.endpoints[firstPort] != firstEndpoint ||
		manager.endpoints[secondPort] != secondEndpoint {
		t.Fatal("proxy endpoint swap replaced an existing listener")
	}
	state := manager.clients["client-one"]
	if state.tcpProxies["first"].endpoint != secondEndpoint ||
		state.tcpProxies["second"].endpoint != firstEndpoint {
		t.Fatal("proxy bindings were not atomically swapped")
	}
}

func TestTCPProxySyncKeepsOldStateWhenNewEndpointConflicts(t *testing.T) {
	t.Parallel()

	manager := newTestTCPProxyManager(t)
	existingPort := uint16(reserveTCPAddress(t).Port)
	manager.Attach("client-one", "session-one", nil)

	initial := manager.Sync(
		"client-one",
		"session-one",
		"request-one",
		protocol.SyncProxies{
			Revision: 1,
			Proxies: []protocol.ProxyDeclaration{
				tcpProxyDeclaration("existing", existingPort),
			},
		},
	)
	if initial.Status != protocol.ProxySyncStatusApplied {
		t.Fatalf("initial proxy synchronization failed: %+v", initial.Error)
	}
	originalEndpoint := manager.endpoints[existingPort]
	occupiedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupiedListener.Close()
	occupiedPort := uint16(occupiedListener.Addr().(*net.TCPAddr).Port)

	rejected := manager.Sync(
		"client-one",
		"session-one",
		"request-two",
		protocol.SyncProxies{
			Revision: 2,
			Proxies: []protocol.ProxyDeclaration{
				tcpProxyDeclaration("existing", existingPort),
				tcpProxyDeclaration("conflicting", occupiedPort),
			},
		},
	)
	if rejected.Status != protocol.ProxySyncStatusRejected ||
		rejected.Error == nil ||
		rejected.Error.Code != protocol.ProxyErrorPortConflict {
		t.Fatalf("expected port conflict, got %+v", rejected)
	}
	state := manager.clients["client-one"]
	if state.revision != 1 ||
		len(state.tcpProxies) != 1 ||
		state.tcpProxies["existing"] == nil ||
		manager.endpoints[existingPort] != originalEndpoint {
		t.Fatal("rejected synchronization changed the previous proxy state")
	}
}

func newTestTCPProxyManager(t *testing.T) *Registry {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	manager := New(
		ctx,
		logging.New("test"),
		"127.0.0.1",
		link.NewBroker(ctx),
		false,
		config.DefaultServer().HTTP,
	)
	t.Cleanup(func() {
		cancel()
		manager.Close()
	})
	return manager
}

func tcpProxyDeclaration(name string, port uint16) protocol.ProxyDeclaration {
	return protocol.ProxyDeclaration{
		Name:       name,
		Type:       protocol.ProxyTypeTCP,
		RemotePort: port,
	}
}

func reserveTCPAddress(t *testing.T) *net.TCPAddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().(*net.TCPAddr)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
