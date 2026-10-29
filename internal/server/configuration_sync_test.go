package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
)

func TestConfigurationRejectsForwardBoundaryBeforeRegistryWork(t *testing.T) {
	for _, test := range []struct {
		name      string
		mode      authentication.Mode
		limits    config.ForwardPermissionLimits
		collision bool
		code      protocol.ForwardErrorCode
	}{
		{"shared_name_collision", authentication.ModeShared, config.ForwardPermissionLimits{}, true, protocol.ForwardErrorInvalidForward},
		{"governed_name_collision", authentication.ModeGoverned, config.ForwardPermissionLimits{}, true, protocol.ForwardErrorInvalidForward},
		{"total_limit", authentication.ModeGoverned, config.ForwardPermissionLimits{MaxTotal: 1}, false, protocol.ForwardErrorLimitExceeded},
		{"tcp_limit", authentication.ModeGoverned, config.ForwardPermissionLimits{MaxTCP: 1}, false, protocol.ForwardErrorLimitExceeded},
		{"udp_limit", authentication.ModeGoverned, config.ForwardPermissionLimits{MaxUDP: 1}, false, protocol.ForwardErrorLimitExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := protocol.SyncConfiguration{Revision: 1, Forwards: []protocol.ForwardDeclaration{
				{Name: "tcp-one", Type: protocol.ForwardTypeTCP, TargetIP: "127.0.0.1", TargetPort: 80},
				{Name: "tcp-two", Type: protocol.ForwardTypeTCP, TargetIP: "127.0.0.1", TargetPort: 80},
				{Name: "udp-one", Type: protocol.ForwardTypeUDP, TargetIP: "127.0.0.1", TargetPort: 53},
				{Name: "udp-two", Type: protocol.ForwardTypeUDP, TargetIP: "127.0.0.1", TargetPort: 53},
			}}
			if test.collision {
				request.Proxies = []protocol.ProxyDeclaration{{Name: "tcp-one", Type: protocol.ProxyTypeTCP, RemotePort: 8080}}
			}
			service := &Service{configuration: newConfigurationManager(config.ServerConfig{
				GovernedClients: map[string]config.GovernedClientConfig{"client": {Permissions: config.GovernedPermissions{
					Forwards: config.GovernedForwardPermissions{Limits: test.limits},
				}}},
			})}
			payload, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			_, err = service.synchronizeConfiguration(configurationSyncSession{
				clientID: "client", sessionID: "session", mode: test.mode, writer: control.NewWriter(&output),
				capabilities: []protocol.Capability{protocol.CapabilityTCP, protocol.CapabilityTCPForward, protocol.CapabilityUDPForward},
			}, protocol.Envelope{RequestID: "request", Payload: payload})
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
			if envelope.RequestID != "request" || result.Revision != 1 || result.Status != protocol.ConfigurationSyncStatusRejected || result.Error == nil || result.Error.Code != protocol.ConfigurationErrorCode(test.code) || result.Error.ResourceKind != protocol.ConfigurationResourceForward || result.Error.Retryable {
				t.Fatalf("unexpected rejection response: %+v", result)
			}
			if len(service.configurationSyncStates) != 0 {
				t.Fatal("rejection published cache state")
			}
		})
	}
}

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
	service.cacheConfigurationSync("client", "session", "request_one", request.Revision, configurationTestFingerprint(t, request), expected)
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
	service.cacheConfigurationSync("client", "session", "request_one", request.Revision, configurationTestFingerprint(t, request), result)

	replayed, _, rejection := service.checkConfigurationSync(
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
		request.Revision,
		configurationTestFingerprint(t, request),
		protocol.SyncConfigurationResult{
			Revision: 1, Status: protocol.ConfigurationSyncStatusApplied,
		},
	)
	request.Forwards[0].TargetPort = 5433
	if replayed, _, rejection := service.checkConfigurationSync(
		"client", "session", "request_one", request,
	); replayed != nil || rejection == nil || rejection.Code != "invalid_request" {
		t.Fatalf("changed payload was not rejected: result=%+v rejection=%+v", replayed, rejection)
	}
}

func configurationTestFingerprint(t *testing.T, request protocol.SyncConfiguration) [sha256.Size]byte {
	t.Helper()
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(payload)
}

func TestConfigurationSyncFingerprintPreservesJSONRepresentation(t *testing.T) {
	service := &Service{}
	request := protocol.SyncConfiguration{Revision: 1}
	_, fingerprint, rejection := service.checkConfigurationSync("client", "session", "request_one", request)
	if rejection != nil || fingerprint != configurationTestFingerprint(t, request) {
		t.Fatalf("unexpected fingerprint or rejection: %v", rejection)
	}
	service.cacheConfigurationSync("client", "session", "request_one", request.Revision, fingerprint,
		protocol.SyncConfigurationResult{Revision: 1, Status: protocol.ConfigurationSyncStatusApplied})
	request.Proxies = []protocol.ProxyDeclaration{}
	_, changedFingerprint, rejection := service.checkConfigurationSync("client", "session", "request_two", request)
	if changedFingerprint != configurationTestFingerprint(t, request) {
		t.Fatal("fingerprint differs from JSON representation")
	}
	// Empty collections must retain the protocol's existing JSON encoding semantics.
	if (changedFingerprint == fingerprint) != (rejection == nil) {
		t.Fatalf("JSON equality and replay validation disagree: %v", rejection)
	}
}

type configurationRejectionFailWriter struct{ err error }

func (writer configurationRejectionFailWriter) Write([]byte) (int, error) { return 0, writer.err }

func TestConfigurationRejectionPreservesWriteFailure(t *testing.T) {
	writeError := errors.New("response write failed")
	service := &Service{}
	_, err := service.rejectConfigurationSync(configurationSyncSession{
		writer: control.NewWriter(configurationRejectionFailWriter{err: writeError}),
	}, "request_one", 7, invalidConfigurationRequest("rejected"))
	if !errors.Is(err, writeError) {
		t.Fatalf("write failure replaced: %v", err)
	}
}

func TestConfigurationRejectionPreservesResponse(t *testing.T) {
	var output bytes.Buffer
	service := &Service{}
	rejection := invalidConfigurationRequest("rejected")
	_, err := service.rejectConfigurationSync(configurationSyncSession{
		writer: control.NewWriter(&output),
	}, "request_one", 7, rejection)
	if !errors.Is(err, errProxyRegistrationRejected) {
		t.Fatalf("unexpected rejection error: %v", err)
	}
	envelope, err := protocol.ReadControl(&output)
	if err != nil {
		t.Fatal(err)
	}
	var result protocol.SyncConfigurationResult
	if err := protocol.DecodePayload(envelope, &result); err != nil {
		t.Fatal(err)
	}
	expected := protocol.SyncConfigurationResult{Revision: 7, Status: protocol.ConfigurationSyncStatusRejected, Error: rejection}
	if envelope.Type != protocol.MessageSyncConfigurationResult || envelope.RequestID != "request_one" || !reflect.DeepEqual(result, expected) {
		t.Fatalf("unexpected rejection response: %+v, %+v", envelope, result)
	}
}
