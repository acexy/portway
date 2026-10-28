package flowcontrol

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	packetdata "github.com/acexy/portway/internal/vnet/packet"
)

func TestReleasedFlowDoesNotResetRateAndBucketsExpire(t *testing.T) {
	var admission Admission
	flow := packetdata.Flow{SourceIP: netip.MustParseAddr("172.20.0.2"), DestinationIP: netip.MustParseAddr("172.20.0.3")}
	now := time.Unix(100, 0)
	for range NewFlowBurst {
		if err := admission.Admit(flow, now, 1); err != nil {
			t.Fatal(err)
		}
		admission.Release(flow.SourceIP, flow.DestinationIP)
	}
	if err := admission.Admit(flow, now, 1); !errors.Is(err, ErrFlowRate) {
		t.Fatalf("release bypassed rate: %v", err)
	}
	flow.DestinationIP = netip.MustParseAddr("172.20.0.4")
	if err := admission.Admit(flow, now, 1); !errors.Is(err, ErrFlowCapacity) {
		t.Fatalf("unbounded bucket count: %v", err)
	}
	if err := admission.Admit(flow, now.Add(3*time.Second), 1); err != nil {
		t.Fatalf("idle bucket did not expire: %v", err)
	}
}
