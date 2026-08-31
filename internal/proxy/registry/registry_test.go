package registry

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
)

func TestManagedReservationRejectsSharedClientBinding(t *testing.T) {
	manager := newTestTCPProxyManager(t)
	port := uint16(reserveTCPAddress(t).Port)
	if err := manager.ConfigureManagedReservations(
		map[string]config.ManagedClientConfig{
			"managed-client": {
				Authentication: config.ClientAuthenticationConfig{ClientID: "managed-client"},
				Configuration: config.ManagedConfiguration{
					Proxies: []config.ProxyConfig{{
						Name: "managed", Type: "tcp", Public: config.ProxyPublicConfig{Port: port},
					}},
				},
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	manager.Attach("shared-client", "shared-session", nil)

	result := manager.Sync(
		"shared-client",
		"shared-session",
		"request-one",
		protocol.SyncProxies{
			Revision: 1,
			Proxies: []protocol.ProxyDeclaration{
				tcpProxyDeclaration("shared", port),
			},
		},
	)
	if result.Status != protocol.ProxySyncStatusRejected ||
		result.Error == nil ||
		result.Error.Code != protocol.ProxyErrorPortConflict {
		t.Fatalf("managed reservation did not reject shared binding: %+v", result)
	}
}

func TestProxySyncRejectsEmptyDeclaration(t *testing.T) {
	t.Parallel()

	manager := newTestTCPProxyManager(t)
	manager.Attach("client-one", "session-one", nil)
	result := manager.Sync(
		"client-one",
		"session-one",
		"request-one",
		protocol.SyncProxies{Revision: 1},
	)
	if result.Status != protocol.ProxySyncStatusRejected ||
		result.Error == nil ||
		result.Error.Code != protocol.ProxyErrorInvalidProxy ||
		result.Error.Retryable {
		t.Fatalf("expected permanent empty proxy rejection, got %+v", result)
	}
}

func TestProxySyncRejectsOversizedRequestIDWithoutCaching(t *testing.T) {
	manager := newTestTCPProxyManager(t)
	manager.Attach("client-a", "session-a", nil)
	result := manager.Sync(
		"client-a",
		"session-a",
		strings.Repeat("x", 129),
		protocol.SyncProxies{Revision: 1},
	)
	if result.Status != protocol.ProxySyncStatusRejected ||
		result.Error == nil || result.Error.Code != protocol.ProxyErrorInvalidRequest {
		t.Fatalf("unexpected result: %+v", result)
	}
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if len(manager.clients["client-a"].requestCache) != 0 {
		t.Fatal("invalid request ID entered the replay cache")
	}
}

func TestManagedReservationTransactionPublishesOnlyOnCommit(t *testing.T) {
	manager := newTestTCPProxyManager(t)
	transaction, err := manager.BeginManagedReservationUpdate(
		map[string]config.ManagedClientConfig{
			"managed-a": {
				Authentication: config.ClientAuthenticationConfig{ClientID: "managed-a"},
				Configuration: config.ManagedConfiguration{Proxies: []config.ProxyConfig{{
					Name: "ssh", Type: protocol.ProxyTypeTCP, Public: config.ProxyPublicConfig{Port: 22022},
				}}},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	manager.mutex.Lock()
	if manager.managedTCPPorts[22022] != "" {
		manager.mutex.Unlock()
		t.Fatal("candidate reservation was visible before commit")
	}
	manager.mutex.Unlock()
	transaction.Commit()
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.managedTCPPorts[22022] != "managed-a" {
		t.Fatal("committed reservation was not published")
	}
}

func TestProxySyncRejectsReusedRequestIDWithDifferentPayload(t *testing.T) {
	t.Parallel()

	manager := newTestTCPProxyManager(t)
	port := uint16(reserveTCPAddress(t).Port)
	manager.Attach("client-one", "session-one", nil)
	first := manager.Sync(
		"client-one", "session-one", "request-one",
		protocol.SyncProxies{
			Revision: 1,
			Proxies:  []protocol.ProxyDeclaration{tcpProxyDeclaration("first", port)},
		},
	)
	if first.Status != protocol.ProxySyncStatusApplied {
		t.Fatalf("initial synchronization failed: %+v", first.Error)
	}
	second := manager.Sync(
		"client-one", "session-one", "request-one",
		protocol.SyncProxies{
			Revision: 2,
			Proxies:  []protocol.ProxyDeclaration{tcpProxyDeclaration("second", port)},
		},
	)
	if second.Status != protocol.ProxySyncStatusRejected ||
		second.Error == nil || second.Error.Code != protocol.ProxyErrorInvalidRequest {
		t.Fatalf("changed request ID payload was not rejected: %+v", second)
	}
	if manager.clients["client-one"].revision != 1 ||
		manager.clients["client-one"].tcpProxies["first"] == nil {
		t.Fatal("rejected request changed the active proxy generation")
	}
}

func TestProxySyncReturnsBoundedCachedResultForHistoricalRequest(t *testing.T) {
	t.Parallel()

	manager := newTestTCPProxyManager(t)
	port := uint16(reserveTCPAddress(t).Port)
	manager.Attach("client-one", "session-one", nil)
	declaration := tcpProxyDeclaration("proxy", port)
	first := manager.Sync(
		"client-one", "session-one", "request-one",
		protocol.SyncProxies{
			Revision: 1,
			Proxies:  []protocol.ProxyDeclaration{declaration},
		},
	)
	if first.Status != protocol.ProxySyncStatusApplied {
		t.Fatalf("first synchronization failed: %+v", first.Error)
	}
	second := manager.Sync(
		"client-one", "session-one", "request-two",
		protocol.SyncProxies{
			Revision: 2,
			Proxies:  []protocol.ProxyDeclaration{declaration},
		},
	)
	if second.Status != protocol.ProxySyncStatusApplied {
		t.Fatalf("second synchronization failed: %+v", second.Error)
	}
	replayed := manager.Sync(
		"client-one", "session-one", "request-one",
		protocol.SyncProxies{
			Revision: 1,
			Proxies:  []protocol.ProxyDeclaration{declaration},
		},
	)
	if !reflect.DeepEqual(replayed, first) {
		t.Fatalf("historical idempotent request did not return its cached result: %+v", replayed)
	}
	if manager.clients["client-one"].revision != 2 {
		t.Fatal("historical idempotent request changed the active revision")
	}
}

func TestHTTPClientCapacityUsesAggregateCounter(t *testing.T) {
	configuration := config.DefaultServer().Proxies.HTTP.HTTPConfig
	configuration.MaxConcurrentRequestsPerClient = 1
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	broker := link.NewBroker(ctx)
	defer broker.Close()
	manager := New(
		ctx,
		logging.New("test"),
		"127.0.0.1",
		broker,
		true,
		configuration,
	)
	defer manager.Close()
	manager.Attach("client-one", "session-one", nil)
	declaration := protocol.ProxyDeclaration{
		Name: "web", Type: protocol.ProxyTypeHTTP, Domain: "example.test",
	}
	binding, err := manager.newHTTPBinding("client-one", "session-one", declaration)
	if err != nil {
		t.Fatal(err)
	}
	state := manager.clients["client-one"]
	state.active = true
	state.httpProxies[declaration.Name] = binding
	state.httpActiveRequests = 1
	manager.httpDomains[declaration.Domain] = binding

	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	response := httptest.NewRecorder()
	manager.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected client capacity rejection, got %d", response.Code)
	}
}

func TestManagedReservationAllowsOwningManagedClient(t *testing.T) {
	manager := newTestTCPProxyManager(t)
	port := uint16(reserveTCPAddress(t).Port)
	clients := map[string]config.ManagedClientConfig{
		"managed-client": {
			Authentication: config.ClientAuthenticationConfig{ClientID: "managed-client"},
			Configuration: config.ManagedConfiguration{
				Proxies: []config.ProxyConfig{{
					Name: "managed", Type: "tcp", Public: config.ProxyPublicConfig{Port: port},
				}},
			},
		},
	}
	if err := manager.ConfigureManagedReservations(clients); err != nil {
		t.Fatal(err)
	}
	manager.AttachAuthenticated(
		"managed-client",
		"managed-session",
		nil,
		authentication.Context{
			Mode:     authentication.ModeManaged,
			ClientID: "managed-client",
		},
		0,
	)

	result := manager.Sync(
		"managed-client",
		"managed-session",
		"request-one",
		protocol.SyncProxies{
			Revision: 1,
			Proxies: []protocol.ProxyDeclaration{
				tcpProxyDeclaration("managed", port),
			},
		},
	)
	if result.Status != protocol.ProxySyncStatusApplied {
		t.Fatalf("managed owner could not claim its reservation: %+v", result.Error)
	}
}

func TestManagedReservationRejectsHotReloadOverActiveSharedBinding(t *testing.T) {
	manager := newTestTCPProxyManager(t)
	port := uint16(reserveTCPAddress(t).Port)
	manager.Attach("shared-client", "shared-session", nil)
	result := manager.Sync(
		"shared-client",
		"shared-session",
		"request-one",
		protocol.SyncProxies{
			Revision: 1,
			Proxies: []protocol.ProxyDeclaration{
				tcpProxyDeclaration("shared", port),
			},
		},
	)
	if result.Status != protocol.ProxySyncStatusApplied {
		t.Fatalf("shared binding setup failed: %+v", result.Error)
	}

	err := manager.ConfigureManagedReservations(
		map[string]config.ManagedClientConfig{
			"managed-client": {
				Authentication: config.ClientAuthenticationConfig{ClientID: "managed-client"},
				Configuration: config.ManagedConfiguration{
					Proxies: []config.ProxyConfig{{
						Name: "managed", Type: "tcp", Public: config.ProxyPublicConfig{Port: port},
					}},
				},
			},
		},
	)
	if err == nil {
		t.Fatal("managed hot-reload reservation accepted an active shared binding")
	}
}

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

func TestProxySyncReportsInactiveSessionAsRetryable(t *testing.T) {
	t.Parallel()

	manager := newTestTCPProxyManager(t)
	result := manager.Sync(
		"missing-client",
		"missing-session",
		"request-one",
		protocol.SyncProxies{Revision: 1},
	)
	if result.Status != protocol.ProxySyncStatusRejected ||
		result.Error == nil ||
		result.Error.Code != protocol.ProxyErrorSessionInactive ||
		!result.Error.Retryable {
		t.Fatalf("expected retryable inactive session rejection, got %+v", result)
	}
}

func TestUDPProxySyncKeepsOldStateWhenNewEndpointConflicts(t *testing.T) {
	t.Parallel()

	manager := newTestTCPProxyManager(t)
	existingPort := uint16(reserveUDPAddress(t).Port)
	manager.Attach("client-one", "session-one", nil)
	initial := manager.Sync(
		"client-one",
		"session-one",
		"request-one",
		protocol.SyncProxies{
			Revision: 1,
			Proxies: []protocol.ProxyDeclaration{
				udpProxyDeclaration("existing", existingPort),
			},
		},
	)
	if initial.Status != protocol.ProxySyncStatusApplied {
		t.Fatalf("initial UDP synchronization failed: %+v", initial.Error)
	}
	originalEndpoint := manager.udpEndpoints[existingPort]
	occupiedConnection, err := net.ListenUDP("udp", &net.UDPAddr{
		IP: net.ParseIP("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer occupiedConnection.Close()
	occupiedPort := uint16(occupiedConnection.LocalAddr().(*net.UDPAddr).Port)

	rejected := manager.Sync(
		"client-one",
		"session-one",
		"request-two",
		protocol.SyncProxies{
			Revision: 2,
			Proxies: []protocol.ProxyDeclaration{
				udpProxyDeclaration("existing", existingPort),
				udpProxyDeclaration("conflicting", occupiedPort),
			},
		},
	)
	if rejected.Status != protocol.ProxySyncStatusRejected ||
		rejected.Error == nil ||
		rejected.Error.Code != protocol.ProxyErrorPortConflict {
		t.Fatalf("expected UDP port conflict, got %+v", rejected)
	}
	state := manager.clients["client-one"]
	if state.revision != 1 ||
		len(state.udpProxies) != 1 ||
		state.udpProxies["existing"] == nil ||
		manager.udpEndpoints[existingPort] != originalEndpoint {
		t.Fatal("rejected synchronization changed the previous UDP proxy state")
	}
}

func TestTCPAndUDPProxiesMayShareNumericPort(t *testing.T) {
	t.Parallel()

	manager := newTestTCPProxyManager(t)
	port := uint16(reserveTCPAddress(t).Port)
	manager.Attach("client-one", "session-one", nil)
	result := manager.Sync(
		"client-one",
		"session-one",
		"request-one",
		protocol.SyncProxies{
			Revision: 1,
			Proxies: []protocol.ProxyDeclaration{
				tcpProxyDeclaration("tcp-service", port),
				udpProxyDeclaration("udp-service", port),
			},
		},
	)
	if result.Status != protocol.ProxySyncStatusApplied {
		t.Fatalf("TCP and UDP numeric port sharing failed: %+v", result.Error)
	}
	if manager.endpoints[port] == nil || manager.udpEndpoints[port] == nil {
		t.Fatal("TCP or UDP endpoint was not published")
	}
}

func TestUDPSuspensionPreservesBindingForOriginalSessionRecovery(t *testing.T) {
	manager := newTestTCPProxyManager(t)
	port := uint16(reserveUDPAddress(t).Port)
	manager.Attach(
		"client-one",
		"session-one",
		control.NewWriter(&bytes.Buffer{}),
	)
	result := manager.Sync(
		"client-one",
		"session-one",
		"request-one",
		protocol.SyncProxies{
			Revision: 1,
			Proxies: []protocol.ProxyDeclaration{
				udpProxyDeclaration("udp-service", port),
			},
		},
	)
	if result.Status != protocol.ProxySyncStatusApplied {
		t.Fatalf("UDP synchronization failed: %+v", result.Error)
	}
	manager.Activate("client-one", "session-one")
	binding := manager.clients["client-one"].udpProxies["udp-service"]

	manager.Suspend("client-one", "session-one")
	manager.Activate("client-one", "session-one")
	if _, err := binding.resolveTarget(); err != nil {
		t.Fatalf("reactivated UDP Binding did not resolve its original Session: %v", err)
	}
	binding.runtime.HandleDatagram(
		netip.MustParseAddrPort("192.0.2.1:40000"),
		[]byte("datagram"),
	)
	if associations := manager.SnapshotStats().UDP.Associations; associations != 1 {
		t.Fatalf("reactivated UDP Binding created %d associations, want 1", associations)
	}
}

func newTestTCPProxyManager(t testing.TB) *Registry {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	manager := New(
		ctx,
		logging.New("test"),
		"127.0.0.1",
		link.NewBroker(ctx),
		false,
		config.DefaultServer().Proxies.HTTP.HTTPConfig,
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

func udpProxyDeclaration(name string, port uint16) protocol.ProxyDeclaration {
	return protocol.ProxyDeclaration{
		Name:       name,
		Type:       protocol.ProxyTypeUDP,
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

func reserveUDPAddress(t *testing.T) *net.UDPAddr {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{
		IP: net.ParseIP("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	address := connection.LocalAddr().(*net.UDPAddr)
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
