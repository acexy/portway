package client

import (
	"errors"
	"testing"

	"github.com/acexy/portway/internal/protocol"
)

func TestValidateVNetAssignment(t *testing.T) {
	valid := protocol.VNetAssignment{
		CIDR: "172.20.0.0/16", ClientIP: "172.20.0.2", ServerIP: "172.20.0.1",
		MTU: 1280, PacketChannels: 4, PoolGeneration: 3, ConfigGeneration: 2,
		State: protocol.VNetStateActive,
	}
	if err := validateVNetAssignment(valid, "governed-a"); err != nil {
		t.Fatalf("validate assignment: %v", err)
	}
	invalid := valid
	invalid.PacketChannels = 9
	if err := validateVNetAssignment(invalid, "governed-a"); err == nil {
		t.Fatal("expected excessive channel count to be rejected")
	}
	invalid = valid
	invalid.ClientIP = invalid.ServerIP
	if err := validateVNetAssignment(invalid, "governed-a"); err == nil {
		t.Fatal("expected duplicate server and client address to be rejected")
	}
}

func TestVNetActivationRequiresExactGenerations(t *testing.T) {
	manager := &clientVNetManager{
		assignment: protocol.VNetAssignment{
			State: protocol.VNetStateActive, PoolGeneration: 8, ConfigGeneration: 5,
		},
		device: inertVNetDevice{},
	}
	if err := manager.activate(protocol.VNetActivate{PoolGeneration: 8, ConfigGeneration: 5}); err != nil {
		t.Fatalf("activate exact generation: %v", err)
	}
	if !manager.activated {
		t.Fatal("expected manager to become activated")
	}
	if err := manager.activate(protocol.VNetActivate{PoolGeneration: 7, ConfigGeneration: 5}); err == nil {
		t.Fatal("expected stale pool generation to be rejected")
	}
}

type inertVNetDevice struct{}

func (inertVNetDevice) Name() string                    { return "test0" }
func (inertVNetDevice) ReadPacket([]byte) (int, error)  { return 0, errors.New("closed") }
func (inertVNetDevice) WritePacket([]byte) (int, error) { return 0, errors.New("closed") }
func (inertVNetDevice) Close() error                    { return nil }
