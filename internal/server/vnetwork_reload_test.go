package server

import (
	"context"
	"errors"
	"testing"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/transport"
)

func TestValidateVNetConfigurationTransitionRejectsLiveNetworkMigration(t *testing.T) {
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
		{"CIDR", func(value *config.VirtualNetworkConfig) { value.CIDR = "172.21.0.0/16" }, "virtual_network.cidr"},
		{"server IP", func(value *config.VirtualNetworkConfig) { value.ServerIP = "172.20.0.10" }, "virtual_network.server_ip"},
		{"connected node IP", func(value *config.VirtualNetworkConfig) { value.Nodes[0].IP = "172.20.0.3" }, "virtual_network.nodes.ip"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := current
			candidate.Nodes = append([]config.VNetNodeConfig(nil), current.Nodes...)
			testCase.change(&candidate)
			err := service.validateVNetConfigurationTransition(current, candidate)
			var restartError restartRequiredError
			if !errors.As(err, &restartError) || restartError.field != testCase.field {
				t.Fatalf("expected restart requirement for %s, got %v", testCase.field, err)
			}
		})
	}
}

type discardConnection struct{}

func (discardConnection) Write(packet []byte) (int, error) { return len(packet), nil }
