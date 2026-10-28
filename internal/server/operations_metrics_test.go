package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	forwardregistry "github.com/acexy/portway/internal/forward/registry"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/vnet"
	packetdata "github.com/acexy/portway/internal/vnet/packet"
)

func operationsMetrics(t *testing.T, service *Service) string {
	t.Helper()
	response := httptest.NewRecorder()
	service.operationsHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("metrics status: %d", response.Code)
	}
	body := response.Body.String()
	seen := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.ContainsAny(fields[0], "{}") || seen[fields[0]] {
			t.Fatalf("invalid, labeled or duplicate metric: %q", line)
		}
		seen[fields[0]] = true
		kind := "gauge"
		if strings.HasSuffix(fields[0], "_total") {
			kind = "counter"
		}
		if !strings.Contains(body, "# TYPE "+fields[0]+" "+kind+"\n") {
			t.Fatalf("missing metric type for %s", fields[0])
		}
	}
	return body
}

func requireOperationsMetric(t *testing.T, body, sample string) {
	t.Helper()
	if !strings.Contains(body, "\n"+sample+"\n") {
		t.Errorf("missing sample %q", sample)
	}
}

func TestOperationsForwardUDPIsolationAndCleanup(t *testing.T) {
	service := NewService(logging.New("test"), config.DefaultServer())
	service.linkBroker = link.NewBroker(context.Background())
	defer service.linkBroker.Close()
	service.forwardRegistry = forwardregistry.New(service.linkBroker,
		func(authentication.Context, protocol.ForwardDeclaration) (bool, bool) { return true, true },
		config.DefaultUDPConfig, func(string, string) bool { return true })
	defer service.forwardRegistry.Close()
	results, registrationError := service.forwardRegistry.Sync("private-client", "private-session",
		control.NewWriter(io.Discard), authentication.Context{}, 10,
		[]protocol.ForwardDeclaration{{Name: "private-forward", Type: protocol.ForwardTypeUDP, TargetIP: "127.0.0.1", TargetPort: 53}})
	if registrationError != nil {
		t.Fatal(registrationError)
	}
	offer := service.forwardRegistry.Offer("private-client", "private-session", protocol.RequestForwardLink{
		RequestID: "request", Name: "private-forward", Type: protocol.ForwardTypeUDP, BindingID: results[0].BindingID,
	})
	if offer.Error != nil {
		t.Fatal(offer.Error)
	}
	body := operationsMetrics(t, service)
	for _, sample := range []string{"portway_forward_bindings 1", "portway_forward_bindings_active 1", "portway_forward_bindings_inactive 0", "portway_forward_udp_associations 1", "portway_forward_udp_pending_associations 1", "portway_udp_associations 0"} {
		requireOperationsMetric(t, body, sample)
	}
	for _, secret := range []string{"private-client", "private-session", "private-forward", "127.0.0.1", offer.Ticket} {
		if secret != "" && strings.Contains(body, secret) {
			t.Fatal("metrics exposed resource identity or binding ticket")
		}
	}
	service.linkBroker.CancelForwardLink("private-client", "private-session", offer.LinkID)
	service.forwardRegistry.Remove("private-client", "private-session")
	body = operationsMetrics(t, service)
	for _, sample := range []string{"portway_forward_bindings 0", "portway_forward_udp_associations 0", "portway_forward_udp_pending_associations 0"} {
		requireOperationsMetric(t, body, sample)
	}
}

func TestOperationsVNetSnapshotsAndConcurrentCollection(t *testing.T) {
	service := NewService(logging.New("test"), config.DefaultServer())
	body := operationsMetrics(t, service)
	for _, sample := range []string{"portway_vnet_enabled 0", "portway_vnet_pools_pending 0", "portway_vnet_policy_rejected_total 0", "portway_vnet_queue_rejected_total 0"} {
		requireOperationsMetric(t, body, sample)
	}
	configuration := config.DefaultServer().VirtualNetwork
	configuration.Enabled = true
	configuration.Nodes = []config.VNetNodeConfig{{ClientID: "private-node", IP: "172.20.0.2"}}
	router, err := vnet.NewRouter(configuration, vnetMaximumTrackedFlows)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := router.AuthorizePeerFlow("unknown-node", packetdata.Flow{
		SourceIP: netip.MustParseAddr("172.20.0.9"), DestinationIP: netip.MustParseAddr("172.20.0.2"), Protocol: 17,
	}, time.Now()); err == nil {
		t.Fatal("unregistered peer flow was authorized")
	}
	broker := vnet.NewPoolBroker()
	defer broker.Close()
	// No device preparation or real network changes are needed for snapshots.
	runtime := &serverVNetRuntime{
		configuration: configuration, router: router, broker: broker,
		sessions:  map[string]serverVNetSession{"private-node": {sessionID: "private-session"}},
		peerPairs: map[string]*serverVNetPeerPair{"private-pair": {active: true}},
	}
	runtime.configGeneration.Store(7)
	service.vnetRuntime = runtime
	spec := vnet.PoolSpec{ClientID: "private-node", SessionID: "private-session", VirtualIP: "172.20.0.2", PoolGeneration: 1, ChannelCount: 2, MTU: 1280, WriteTimeout: time.Second}
	if _, err := broker.Prepare(spec, time.Minute); err != nil {
		t.Fatal(err)
	}
	body = operationsMetrics(t, service)
	for _, sample := range []string{"portway_vnet_policy_rejected_total 1", "portway_vnet_enabled 1", "portway_vnet_device_open 0", "portway_vnet_nodes 1", "portway_vnet_sessions 1", "portway_vnet_configuration_generation 7", "portway_vnet_pools_pending 1", "portway_vnet_pools_active 0", "portway_vnet_channels_active 0", "portway_vnet_peer_pairs 1", "portway_vnet_direct_pairs 1"} {
		requireOperationsMetric(t, body, sample)
	}
	if strings.Contains(body, "private-") || strings.Contains(body, "172.20.") {
		t.Fatal("VNet metrics exposed node identity or topology")
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 30 {
			broker.Remove(spec.ClientID, spec.SessionID)
			if _, err := broker.Prepare(spec, time.Minute); err != nil {
				t.Error(err)
			}
			runtime.mutex.Lock()
			runtime.configuration.Enabled = !runtime.configuration.Enabled
			runtime.mutex.Unlock()
		}
	})
	for range 30 {
		operationsMetrics(t, service)
	}
	workers.Wait()
	broker.Close()
	configuration.Enabled = false
	if err := router.ApplyPolicy(configuration); err != nil {
		t.Fatal(err)
	}
	body = operationsMetrics(t, service)
	requireOperationsMetric(t, body, "portway_vnet_pools_pending 0")
	requireOperationsMetric(t, body, "portway_vnet_policy_rejected_total 1")
	// Feature unavailability must not alter process readiness.
	service.ready.Store(true)
	response := httptest.NewRecorder()
	service.operationsHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusOK {
		t.Fatal("VNet device absence changed process readiness")
	}
}

func TestOperationsDormantForwardIsNotReportedAsActive(t *testing.T) {
	service := NewService(logging.New("test"), config.DefaultServer())
	service.linkBroker = link.NewBroker(context.Background())
	defer service.linkBroker.Close()
	service.forwardRegistry = forwardregistry.New(service.linkBroker,
		func(authentication.Context, protocol.ForwardDeclaration) (bool, bool) { return true, false },
		config.DefaultUDPConfig, func(string, string) bool { return true })
	defer service.forwardRegistry.Close()
	_, registrationError := service.forwardRegistry.Sync("client", "session", control.NewWriter(io.Discard),
		authentication.Context{}, 10, []protocol.ForwardDeclaration{
			{Name: "database", Type: protocol.ForwardTypeTCP, TargetIP: "127.0.0.1", TargetPort: 5432},
		})
	if registrationError != nil {
		t.Fatal(registrationError)
	}
	body := operationsMetrics(t, service)
	for _, sample := range []string{"portway_forward_bindings 1", "portway_forward_bindings_active 0", "portway_forward_bindings_inactive 1", "portway_tcp_forwards 1", "portway_forward_links_active 0"} {
		requireOperationsMetric(t, body, sample)
	}
}
