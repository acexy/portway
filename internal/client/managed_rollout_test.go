package client

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

func TestPendingManagedConfigurationPreservesCandidateOnDuplicateOrConflict(t *testing.T) {
	logger := logging.New("test")
	service := NewService(logger, config.ClientConfig{})
	preparation := emptyManagedPreparation(t, 2)
	pending, err := service.prepareManagedConfiguration(
		context.Background(), logger, "session", nil, nil, preparation, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.close()
	duplicate, err := service.prepareManagedConfiguration(
		context.Background(), logger, "session", nil, nil, preparation, pending,
	)
	if err != nil || duplicate != pending {
		t.Fatalf("duplicate preparation replaced the candidate: %v", err)
	}
	preparation.Revision++
	if _, err := service.prepareManagedConfiguration(
		context.Background(), logger, "session", nil, nil, preparation, pending,
	); !errors.Is(err, transport.ErrProtocol) {
		t.Fatalf("conflicting preparation error = %v", err)
	}
	if pending.forwards.context.Err() != nil || service.managedStatus.Revision != 0 {
		t.Fatal("preparation closed the candidate or published its revision")
	}
	service.managedStatus = protocol.ManagedConfigStatus{Revision: preparation.Revision + 1}
	if _, err := service.prepareManagedConfiguration(
		context.Background(), logger, "session", nil, nil, preparation, nil,
	); !errors.Is(err, transport.ErrProtocol) {
		t.Fatalf("stale preparation error = %v", err)
	}
}

func TestPendingManagedConfigurationActivationTransfersOwnership(t *testing.T) {
	logger := logging.New("test")
	original := []config.ProxyConfig{{Name: "original", Type: protocol.ProxyTypeTCP}}
	service := NewService(logger, config.ClientConfig{Proxies: original})
	current := newForwardManager(context.Background(), logger, "client", "session", nil, nil, nil)
	defer current.close()
	links := newLinkManager(context.Background(), logger, "client", original, "session", nil, nil)
	defer links.close()
	preparation := emptyManagedPreparation(t, 2)
	preparation.Proxies = []protocol.ManagedProxy{{
		Name: "replacement", Type: protocol.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 8080, RemotePort: 18080,
	}}
	digest, err := protocol.ManagedConfigurationDigest(preparation.Proxies, preparation.Forwards)
	if err != nil {
		t.Fatal(err)
	}
	preparation.Digest = digest
	pending, err := service.prepareManagedConfiguration(
		context.Background(), logger, "session", nil, nil, preparation, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.close()
	activation := protocol.ManagedConfigActivate{Revision: preparation.Revision + 1, Digest: preparation.Digest}
	next, err := pending.activate(service, current, links, activation)
	if !errors.Is(err, transport.ErrProtocol) || next != current || current.context.Err() != nil {
		t.Fatalf("mismatched activation changed the current runtime: %v", err)
	}
	if service.managedStatus.Revision != 0 {
		t.Fatal("mismatched activation published its revision")
	}
	if proxies := service.runtimeProxySnapshot(); len(proxies) != 1 || proxies[0].Name != "original" {
		t.Fatal("mismatched activation replaced the proxy configuration")
	}
	candidate := pending.forwards
	activation.Revision = preparation.Revision
	next, err = pending.activate(service, current, links, activation)
	if err != nil {
		t.Fatal(err)
	}
	if next != candidate || pending.forwards != nil || current.context.Err() == nil || next.context.Err() != nil {
		t.Fatal("activation did not transfer ownership to the candidate")
	}
	defer next.close()
	pending.close()
	if next.context.Err() != nil {
		t.Fatal("candidate cleanup closed the transferred runtime")
	}
	if service.managedStatus != pending.status {
		t.Fatal("activation did not publish the prepared revision")
	}
	if proxies := service.runtimeProxySnapshot(); len(proxies) != 1 || proxies[0].Name != "replacement" {
		t.Fatal("activation did not publish the prepared proxies")
	}
	if _, exists := links.findProxy("replacement", protocol.ProxyTypeTCP); !exists {
		t.Fatal("activation did not update Link authorization")
	}
	if _, exists := links.findProxy("original", protocol.ProxyTypeTCP); exists {
		t.Fatal("activation retained the previous proxy in Link authorization")
	}
}

func emptyManagedPreparation(t *testing.T, revision uint64) protocol.ManagedConfigPrepare {
	t.Helper()
	proxies := []protocol.ManagedProxy{}
	forwards := []protocol.ManagedForward{}
	digest, err := protocol.ManagedConfigurationDigest(proxies, forwards)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.ManagedConfigPrepare{Revision: revision, Digest: digest, Proxies: proxies, Forwards: forwards}
}

func TestPendingManagedActivationFailureReturnsRemainingRuntime(t *testing.T) {
	for _, validBindings := range []bool{false, true} {
		name := "invalid bindings preserve current"
		if validBindings {
			name = "listen failure leaves no active runtime"
		}
		t.Run(name, func(t *testing.T) {
			occupied, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()
			logger := logging.New("test")
			service := NewService(logger, config.ClientConfig{})
			current := newForwardManager(context.Background(), logger, "client", "session", nil, nil, nil)
			defer current.close()
			candidate := newForwardManager(context.Background(), logger, "client", "session", nil, nil, []config.ForwardConfig{{
				Name: "database", Type: protocol.ForwardTypeTCP,
				Listen: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(occupied.Addr().(*net.TCPAddr).Port)},
			}})
			pending := &pendingManagedConfiguration{
				forwards: candidate,
				status:   protocol.ManagedConfigStatus{Revision: 2, Digest: "test-digest"},
			}
			defer pending.close()
			activation := protocol.ManagedConfigActivate{Revision: 2, Digest: "test-digest"}
			if validBindings {
				activation.Forwards = []protocol.ForwardResult{{
					Name: "database", Type: protocol.ForwardTypeTCP, BindingID: "binding", Active: true,
				}}
			}
			next, err := pending.activate(service, current, nil, activation)
			if err == nil {
				t.Fatal("invalid activation succeeded")
			}
			if validBindings {
				if next != nil || current.context.Err() == nil || candidate.context.Err() == nil {
					t.Fatal("listen failure did not close both runtimes and return nil")
				}
			} else if next != current || current.context.Err() != nil {
				t.Fatal("binding validation failure discarded the active runtime")
			}
			if service.managedStatus.Revision != 0 {
				t.Fatal("failed activation published a new revision")
			}
		})
	}
}
