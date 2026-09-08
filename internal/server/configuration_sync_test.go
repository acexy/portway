package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
)

func TestSynchronizeConfigurationReplaysCompleteResultBeforeRegistryWork(t *testing.T) {
	service := &Service{}
	request := protocol.SyncConfiguration{
		Revision: 1,
		Forwards: []protocol.ForwardDeclaration{{
			Name: "database", Type: protocol.ForwardTypeTCP,
			TargetIP: "10.0.0.1", TargetPort: 5432,
		}},
	}
	expected := protocol.SyncConfigurationResult{
		Revision: 1, Status: protocol.ConfigurationSyncStatusApplied,
		Forwards: []protocol.ForwardResult{{Name: "database"}},
	}
	service.cacheConfigurationSync("client", "session", "request_one", request, expected)
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	result, err := service.synchronizeConfiguration(configurationSyncSession{
		clientID: "client", sessionID: "session", mode: authentication.ModeShared,
		writer: control.NewWriter(&output),
	}, protocol.Envelope{RequestID: "request_two", Payload: payload})
	if err != nil || !reflect.DeepEqual(result, expected) {
		t.Fatalf("replayed result = %+v, error = %v", result, err)
	}
	if output.Len() != 0 {
		t.Fatal("successful synchronization wrote a response before the control session could activate")
	}
}

func TestSynchronizeConfigurationRejectsUnnegotiatedForwardBeforeRegistryWork(t *testing.T) {
	request := protocol.SyncConfiguration{
		Revision: 1,
		Forwards: []protocol.ForwardDeclaration{{
			Name: "database", Type: protocol.ForwardTypeTCP,
			TargetIP: "10.0.0.1", TargetPort: 5432,
		}},
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	service := &Service{}
	_, err = service.synchronizeConfiguration(configurationSyncSession{
		clientID: "client", sessionID: "session", mode: authentication.ModeShared,
		writer: control.NewWriter(&output),
	}, protocol.Envelope{RequestID: "request_one", Payload: payload})
	if !errors.Is(err, errProxyRegistrationRejected) {
		t.Fatalf("unexpected rejection: %v", err)
	}
	envelope, err := protocol.ReadControl(&output)
	if err != nil {
		t.Fatal(err)
	}
	var result protocol.SyncConfigurationResult
	if err := protocol.DecodePayload(envelope, &result); err != nil {
		t.Fatal(err)
	}
	if envelope.RequestID != "request_one" || result.Status != protocol.ConfigurationSyncStatusRejected ||
		result.Error == nil || result.Error.Code != protocol.ConfigurationErrorForwardTypeNotAllowed ||
		result.Error.ResourceKind != protocol.ConfigurationResourceForward || result.Error.ResourceName != "database" {
		t.Fatalf("unexpected correlated rejection: %+v", result)
	}
	if len(service.configurationSyncStates) != 0 {
		t.Fatal("rejection published configuration cache state")
	}
}

func TestConfigurationSyncCacheReplaysCompleteResult(t *testing.T) {
	service := &Service{}
	request := protocol.SyncConfiguration{
		Revision: 1,
		Proxies: []protocol.ProxyDeclaration{{
			Name: "ssh", Type: protocol.ProxyTypeTCP, RemotePort: 22022,
		}},
		Forwards: []protocol.ForwardDeclaration{},
	}
	result := protocol.SyncConfigurationResult{
		Revision: 1,
		Status:   protocol.ConfigurationSyncStatusApplied,
		Proxies: []protocol.ProxyResult{{
			Name: "ssh", Status: protocol.ProxyStatusActive, RemotePort: 22022,
		}},
		Forwards: []protocol.ForwardResult{},
	}
	service.cacheConfigurationSync("client", "session", "request_one", request, result)

	replayed, rejection := service.checkConfigurationSync(
		"client", "session", "request_two", request,
	)
	if rejection != nil || replayed == nil || replayed.Status != result.Status ||
		len(replayed.Proxies) != 1 {
		t.Fatalf("unexpected replay result: result=%+v rejection=%+v", replayed, rejection)
	}
}

func TestConfigurationSyncCacheRejectsChangedRequestIDPayload(t *testing.T) {
	service := &Service{}
	request := protocol.SyncConfiguration{
		Revision: 1, Proxies: []protocol.ProxyDeclaration{},
		Forwards: []protocol.ForwardDeclaration{{
			Name: "database", Type: protocol.ForwardTypeTCP,
			TargetIP: "10.0.0.1", TargetPort: 5432,
		}},
	}
	service.cacheConfigurationSync(
		"client",
		"session",
		"request_one",
		request,
		protocol.SyncConfigurationResult{
			Revision: 1, Status: protocol.ConfigurationSyncStatusApplied,
		},
	)
	request.Forwards[0].TargetPort = 5433
	if replayed, rejection := service.checkConfigurationSync(
		"client", "session", "request_one", request,
	); replayed != nil || rejection == nil || rejection.Code != "invalid_request" {
		t.Fatalf("changed payload was not rejected: result=%+v rejection=%+v", replayed, rejection)
	}
}
