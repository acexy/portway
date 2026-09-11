package server

import (
	"testing"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
)

func TestNegotiateVNetCapabilityRequiresConfiguredManagedClient(t *testing.T) {
	configuration := config.DefaultServer()
	configuration.VirtualNetwork.Nodes = []config.VNetNodeConfig{{
		ClientID: "client-a",
		IP:       "172.20.0.2",
	}}
	service := NewService(logging.New("test"), configuration)
	capabilities := []protocol.Capability{protocol.CapabilityVNetIPv4}

	negotiated := service.negotiateCapabilities(capabilities, authentication.Context{
		Mode:     authentication.ModeManaged,
		ClientID: "client-a",
	})
	if len(negotiated) != 1 || negotiated[0] != protocol.CapabilityVNetIPv4 {
		t.Fatalf("configured managed client did not negotiate VNet: %v", negotiated)
	}
	negotiated = service.negotiateCapabilities(capabilities, authentication.Context{
		Mode:     authentication.ModeShared,
		ClientID: "client-a",
	})
	if len(negotiated) != 0 {
		t.Fatalf("shared client negotiated VNet: %v", negotiated)
	}
	negotiated = service.negotiateCapabilities(capabilities, authentication.Context{
		Mode:     authentication.ModeGoverned,
		ClientID: "client-a",
	})
	if len(negotiated) != 0 {
		t.Fatalf("governed client negotiated VNet: %v", negotiated)
	}
	negotiated = service.negotiateCapabilities(capabilities, authentication.Context{
		Mode:     authentication.ModeManaged,
		ClientID: "client-b",
	})
	if len(negotiated) != 0 {
		t.Fatalf("unconfigured managed client negotiated VNet: %v", negotiated)
	}
}

func TestNegotiateLoopbackVNetRequiresUserspaceCapability(t *testing.T) {
	configuration := config.DefaultServer()
	configuration.VirtualNetwork.NetworkMode = config.VNetNetworkModeLoopback
	configuration.VirtualNetwork.Nodes = []config.VNetNodeConfig{{ClientID: "client-a", IP: "172.20.0.2"}}
	service := NewService(logging.New("test"), configuration)
	authenticationContext := authentication.Context{Mode: authentication.ModeManaged, ClientID: "client-a"}
	if negotiated := service.negotiateCapabilities(
		[]protocol.Capability{protocol.CapabilityVNetIPv4}, authenticationContext,
	); len(negotiated) != 0 {
		t.Fatalf("loopback VNet negotiated without userspace capability: %v", negotiated)
	}
	negotiated := service.negotiateCapabilities([]protocol.Capability{
		protocol.CapabilityVNetIPv4, protocol.CapabilityVNetLoopback,
	}, authenticationContext)
	if len(negotiated) != 2 {
		t.Fatalf("loopback VNet capabilities were not negotiated: %v", negotiated)
	}
}
