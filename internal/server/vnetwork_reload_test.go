package server

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
	"github.com/acexy/portway/internal/vnet"
)

func TestVNetPolicyOnlyReloadKeepsAssignmentGenerationValid(t *testing.T) {
	configuration := config.DefaultServer().VirtualNetwork
	configuration.Enabled = true
	configuration.PacketChannels = 1
	configuration.ServerPorts.TCP.PortRanges = []config.PortRange{{Start: 22, End: 22}}
	configuration.Nodes = []config.VNetNodeConfig{{ClientID: "managed-a", IP: "172.20.0.2"}}
	runtime := newServerVNetRuntime(context.Background(), logging.New("test"), configuration, nil)
	runtime.prepareNetwork = func(context.Context, vnet.NetworkSpec) (vnet.Device, error) {
		return nil, errors.New("test network is not installed")
	}
	defer runtime.Close()
	runtime.attach("managed-a", "session-a", transport.Generation(1), authentication.Context{
		Mode: authentication.ModeManaged, ClientID: "managed-a",
	}, control.NewWriter(discardConnection{}))
	if err := runtime.assign("managed-a", "session-a"); err != nil {
		t.Fatalf("assign VNet: %v", err)
	}
	runtime.mutex.RLock()
	assignmentGeneration := runtime.sessions["managed-a"].configGeneration
	poolGeneration := runtime.sessions["managed-a"].poolGeneration
	runtime.mutex.RUnlock()

	candidate := configuration
	candidate.ServerPorts.TCP.PortRanges = []config.PortRange{{Start: 80, End: 80}}
	runtime.applyConfiguration(candidate, assignmentGeneration+1)
	if err := runtime.replaceFailedPool("managed-a", "session-a", protocol.VNetStatus{
		State: protocol.VNetStateFailed, PoolGeneration: poolGeneration,
		ConfigGeneration: assignmentGeneration,
	}); err != nil {
		t.Fatalf("replace pool after policy-only reload: %v", err)
	}
	runtime.mutex.RLock()
	replacementGeneration := runtime.sessions["managed-a"].configGeneration
	runtime.mutex.RUnlock()
	if replacementGeneration != assignmentGeneration+1 {
		t.Fatalf("replacement assignment generation = %d, want %d", replacementGeneration, assignmentGeneration+1)
	}
}

func TestValidateVNetConfigurationTransitionAllowsAddressMigration(t *testing.T) {
	current := config.DefaultServer().VirtualNetwork
	current.Enabled = true
	current.Nodes = []config.VNetNodeConfig{{ClientID: "managed-a", IP: "172.20.0.2"}}
	runtime := newServerVNetRuntime(context.Background(), logging.New("test"), current, nil)
	defer runtime.Close()
	runtime.attach("managed-a", "session-a", transport.Generation(1), authentication.Context{
		Mode: authentication.ModeManaged, ClientID: "managed-a",
	}, control.NewWriter(discardConnection{}))
	service := &Service{vnetRuntime: runtime}

	testCases := []struct {
		name   string
		change func(*config.VirtualNetworkConfig)
		field  string
	}{
		{"CIDR", func(value *config.VirtualNetworkConfig) { value.CIDR = "172.21.0.0/16" }, ""},
		{"server IP", func(value *config.VirtualNetworkConfig) { value.ServerIP = "172.20.0.10" }, ""},
		{"connected node IP", func(value *config.VirtualNetworkConfig) { value.Nodes[0].IP = "172.20.0.3" }, ""},
		{"network mode", func(value *config.VirtualNetworkConfig) {
			value.NetworkMode = config.VNetNetworkModeLoopback
		}, "virtual_network.network_mode"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := current
			candidate.Nodes = append([]config.VNetNodeConfig(nil), current.Nodes...)
			testCase.change(&candidate)
			err := service.validateVNetConfigurationTransition(current, candidate)
			if testCase.field == "" {
				if err != nil {
					t.Fatalf("address migration requires restart: %v", err)
				}
				return
			}
			var restartError restartRequiredError
			if !errors.As(err, &restartError) || restartError.field != testCase.field {
				t.Fatalf("expected restart requirement for %s, got %v", testCase.field, err)
			}
		})
	}
}

type notifyingVNetDevice struct {
	*blockingVNetDevice
	started chan struct{}
	once sync.Once
}

func (device *notifyingVNetDevice) ReadPacket(packet []byte) (int, error) {
	device.once.Do(func() { close(device.started) })
	return device.blockingVNetDevice.ReadPacket(packet)
}

func TestVNetMigrationInstallsLatestConfiguration(t *testing.T) {
	configuration := config.DefaultServer().VirtualNetwork
	configuration.Enabled = true
	oldDevice := newBlockingVNetDevice()
	runtime := newServerVNetRuntime(context.Background(), logging.New("test"), configuration, oldDevice)
	defer runtime.Close()
	attempts := make(chan vnet.NetworkSpec, 2)
	latestDevice := &notifyingVNetDevice{blockingVNetDevice: newBlockingVNetDevice(), started: make(chan struct{})}
	runtime.prepareNetwork = func(ctx context.Context, spec vnet.NetworkSpec) (vnet.Device, error) {
		attempts <- spec
		if spec.CIDR == "172.21.0.0/16" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return latestDevice, nil
	}
	intermediate := configuration
	intermediate.CIDR, intermediate.ServerIP = "172.21.0.0/16", "172.21.0.1"
	runtime.applyConfiguration(intermediate, 2)
	select {
	case spec := <-attempts:
		if spec.CIDR != intermediate.CIDR {
			t.Fatal("wrong initial migration target")
		}
	case <-time.After(time.Second):
		t.Fatal("address change did not automatically start installation")
	}
	select {
	case <-oldDevice.closed:
	default:
		t.Fatal("old device remained open during migration")
	}
	latest := intermediate
	latest.CIDR, latest.ServerIP = "172.22.0.0/16", "172.22.0.1"
	runtime.applyConfiguration(latest, 3)
	select {
	case spec := <-attempts:
		if spec.CIDR != latest.CIDR || spec.LocalIP != latest.ServerIP {
			t.Fatal("superseded installer did not switch to the latest configuration")
		}
	case <-time.After(time.Second):
		t.Fatal("latest migration was lost while the previous installer was running")
	}
	select {
	case <-latestDevice.started:
	case <-time.After(time.Second):
		t.Fatal("latest device was not activated")
	}
}

func TestVNetNodeAddressMigrationPreservesServerDeviceAndSession(t *testing.T) {
	configuration := config.DefaultServer().VirtualNetwork
	configuration.Enabled = true
	configuration.Nodes = []config.VNetNodeConfig{{ClientID: "managed-a", IP: "172.20.0.2"}}
	device := newBlockingVNetDevice()
	runtime := newServerVNetRuntime(context.Background(), logging.New("test"), configuration, device)
	defer runtime.Close()
	var messages bytes.Buffer
	runtime.attach("managed-a", "session-a", 1, authentication.Context{
		Mode: authentication.ModeManaged, ClientID: "managed-a",
	}, control.NewWriter(&messages))
	candidate := configuration
	candidate.Nodes = []config.VNetNodeConfig{{ClientID: "managed-a", IP: "172.20.0.3"}}
	runtime.applyConfiguration(candidate, 2)
	if runtime.device != device || runtime.sessions["managed-a"].sessionID != "session-a" {
		t.Fatal("node migration replaced server device or control session")
	}
	for messages.Len() != 0 {
		envelope, err := protocol.ReadControl(&messages)
		if err != nil {
			t.Fatal(err)
		}
		if envelope.Type == protocol.MessageVNetAssignment {
			var assignment protocol.VNetAssignment
			if err := protocol.DecodePayload(envelope, &assignment); err != nil {
				t.Fatal(err)
			}
			if assignment.ClientIP != "172.20.0.3" || assignment.State != protocol.VNetStateEnabled {
				t.Fatalf("new node assignment = %+v", assignment)
			}
			return
		}
	}
	t.Fatal("node migration did not send its new assignment")
}

type discardConnection struct{}

func (discardConnection) Write(packet []byte) (int, error) { return len(packet), nil }
