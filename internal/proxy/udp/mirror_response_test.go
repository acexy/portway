package udp

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/link"
)

type recordingResponseSocket struct {
	packets chan string
}

func (socket *recordingResponseSocket) WriteToUDPAddrPort(payload []byte, _ netip.AddrPort) (int, error) {
	socket.packets <- string(payload)
	return len(payload), nil
}

func (socket *recordingResponseSocket) SetWriteDeadline(time.Time) error { return nil }

func TestExistingAssociationFollowsPrimaryChanges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		configuration := config.DefaultUDPConfig()
		source := netip.MustParseAddrPort("192.0.2.1:1234")
		limiter := NewLimiter(configuration)
		lease, allowed := limiter.Acquire("client", "proxy", source.Addr(), time.Now())
		if !allowed {
			t.Fatal("association rejected")
		}
		socket := &recordingResponseSocket{packets: make(chan string, 4)}
		binding := &Binding{
			context: context.Background(), configuration: configuration,
			endpoint:     &Endpoint{responses: NewResponseWriter(socket)},
			associations: make(map[netip.AddrPort]*association),
		}
		candidate := newAssociation(binding, source, link.Target{}, lease)
		binding.associations[source] = candidate
		binding.waitGroup.Add(1)
		candidate.complete(true)
		stream, backend := net.Pipe()
		defer backend.Close()
		done := make(chan error, 1)
		go func() { done <- candidate.forward(context.Background(), stream) }()
		for _, enabled := range []bool{false, true, false, true} {
			binding.SetResponseEnabled(enabled)
			if err := WriteDatagram(backend, []byte("response"), configuration.MaxDatagramSize); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			select {
			case payload := <-socket.packets:
				if !enabled || payload != "response" {
					t.Fatalf("response from ineligible member: %q", payload)
				}
			default:
				if enabled {
					t.Fatal("new Primary response discarded by existing association")
				}
			}
		}
		candidate.Close()
		<-done
		binding.waitGroup.Wait()
		if limiter.SnapshotStats().Associations != 0 {
			t.Fatal("association capacity leaked")
		}
	})
}
