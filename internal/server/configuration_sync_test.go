package server

import (
	"testing"

	"github.com/acexy/portway/internal/protocol"
)

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
