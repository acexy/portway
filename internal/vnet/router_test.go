package vnet

import (
	"errors"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
)

func TestRouterAuthorizesRequestAndReply(t *testing.T) {
	router := testRouter(t)
	now := time.Unix(1, 0)
	request := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	destination, err := router.RouteClientPacket("client-a", request, now)
	if err != nil {
		t.Fatalf("route request: %v", err)
	}
	if destination.Kind != DestinationClient || destination.ClientID != "client-b" {
		t.Fatalf("unexpected request destination: %+v", destination)
	}
	reply := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 3}, 8080, [4]byte{172, 20, 0, 2}, 50000)
	reply[33] = 0x10
	destination, err = router.RouteClientPacket("client-b", reply, now.Add(time.Millisecond))
	if err != nil {
		t.Fatalf("route reply: %v", err)
	}
	if destination.ClientID != "client-a" {
		t.Fatalf("unexpected reply destination: %+v", destination)
	}
}

func TestRouterRejectsSpoofingAndUnsolicitedReply(t *testing.T) {
	router := testRouter(t)
	now := time.Unix(1, 0)
	packet := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 9}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-a", packet, now); !errors.Is(err, ErrSourceRejected) {
		t.Fatalf("expected spoofing rejection, got %v", err)
	}
	packet = testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 3}, 8080, [4]byte{172, 20, 0, 2}, 50000)
	packet[33] = 0x10
	if _, err := router.RouteClientPacket("client-b", packet, now); !errors.Is(err, ErrFlowRejected) {
		t.Fatalf("expected unsolicited reply rejection, got %v", err)
	}
}

func TestRouterPolicyReloadRevokesFlow(t *testing.T) {
	router := testRouter(t)
	now := time.Unix(1, 0)
	request := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-a", request, now); err != nil {
		t.Fatalf("route request: %v", err)
	}
	configuration := testVNetConfiguration()
	configuration.Nodes[1].Ports = config.VNetPortPermissions{}
	if err := router.ApplyPolicy(configuration); err != nil {
		t.Fatalf("apply policy: %v", err)
	}
	reply := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 3}, 8080, [4]byte{172, 20, 0, 2}, 50000)
	reply[33] = 0x10
	if _, err := router.RouteClientPacket("client-b", reply, now.Add(time.Millisecond)); !errors.Is(err, ErrFlowRejected) {
		t.Fatalf("expected revoked flow rejection, got %v", err)
	}
}

func TestRouterPolicyReloadRevokesDeletedClientFlows(t *testing.T) {
	router := testRouter(t)
	now := time.Unix(1, 0)
	request := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 1}, 22)
	if _, err := router.RouteClientPacket("client-a", request, now); err != nil {
		t.Fatalf("route request: %v", err)
	}
	configuration := testVNetConfiguration()
	configuration.Nodes = configuration.Nodes[1:]
	if err := router.ApplyPolicy(configuration); err != nil {
		t.Fatalf("apply policy: %v", err)
	}
	reply := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 1}, 22, [4]byte{172, 20, 0, 2}, 50000)
	reply[33] = 0x10
	if _, err := router.RouteServerPacket(reply, now.Add(time.Millisecond)); !errors.Is(err, ErrTargetUnavailable) {
		t.Fatalf("expected deleted client flow to be revoked, got %v", err)
	}
}

func TestRouterRemoveClientRevokesRelatedFlows(t *testing.T) {
	router := testRouter(t)
	now := time.Unix(1, 0)
	request := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-a", request, now); err != nil {
		t.Fatalf("route request: %v", err)
	}
	router.RemoveClient("client-a")
	reply := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 3}, 8080, [4]byte{172, 20, 0, 2}, 50000)
	reply[33] = 0x10
	if _, err := router.RouteClientPacket("client-b", reply, now.Add(time.Millisecond)); !errors.Is(err, ErrFlowRejected) {
		t.Fatalf("expected disconnected client flow to be revoked, got %v", err)
	}
}

func TestRouterReassignedIPDoesNotInheritPreviousFlows(t *testing.T) {
	router := testRouter(t)
	now := time.Now()
	request := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-a", request, now); err != nil {
		t.Fatal(err)
	}
	configuration := testVNetConfiguration()
	configuration.Nodes[1].ClientID = "replacement-client"
	if err := router.ApplyPolicy(configuration); err != nil {
		t.Fatal(err)
	}
	reply := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 3}, 8080, [4]byte{172, 20, 0, 2}, 50000)
	reply[33] = 0x10
	if _, err := router.RouteClientPacket("replacement-client", reply, now); !errors.Is(err, ErrFlowRejected) {
		t.Fatalf("new IP owner inherited old flow authorization: %v", err)
	}
}

func testRouter(t *testing.T) *Router {
	t.Helper()
	router, err := NewRouter(testVNetConfiguration(), 16)
	if err != nil {
		t.Fatalf("create router: %v", err)
	}
	return router
}

func TestRouterCapacityCleanupIsRateLimited(t *testing.T) {
	router := testRouter(t)
	router.maxFlows = 1
	now := time.Unix(1, 0)
	request := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-a", request, now); err != nil {
		t.Fatal(err)
	}
	other := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, 50001, [4]byte{172, 20, 0, 3}, 8080)
	if _, err := router.RouteClientPacket("client-a", other, now); !errors.Is(err, ErrFlowCapacity) {
		t.Fatalf("full router = %v", err)
	}
	// Make the occupied entry expire before the next capacity scan is permitted.
	for key, state := range router.flows {
		state.expiresAt = now.Add(time.Millisecond)
		router.flows[key] = state
	}
	if _, err := router.RouteClientPacket("client-a", other, now.Add(2*time.Millisecond)); !errors.Is(err, ErrFlowCapacity) {
		t.Fatalf("unexpected repeated capacity scan: %v", err)
	}
	if _, err := router.RouteClientPacket("client-a", other, now.Add(time.Second)); err != nil {
		t.Fatalf("expired capacity was not recovered: %v", err)
	}
}

func testVNetConfiguration() config.VirtualNetworkConfig {
	return config.VirtualNetworkConfig{
		Enabled:        true,
		CIDR:           "172.20.0.0/16",
		ServerIP:       "172.20.0.1",
		PacketChannels: 4,
		ServerPorts: config.VNetPortPermissions{TCP: config.ForwardPortPermission{
			PortRanges: []config.PortRange{{Start: 22, End: 22}},
		}},
		Nodes: []config.VNetNodeConfig{
			{ClientID: "client-a", IP: "172.20.0.2"},
			{
				ClientID: "client-b",
				IP:       "172.20.0.3",
				Ports: config.VNetPortPermissions{TCP: config.ForwardPortPermission{
					PortRanges: []config.PortRange{{Start: 8080, End: 8080}},
				}},
			},
		},
	}
}
