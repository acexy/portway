package server

import (
	"net"
	"testing"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
)

func TestInboundAdmissionIsBoundedAndReusable(t *testing.T) {
	service := NewService(logging.New("test"), config.DefaultServer())
	releases := make([]func(), 0, maxUnaffiliatedInboundConnections)
	for range maxUnaffiliatedInboundConnections {
		release, admitted := service.acquireInboundAdmission()
		if !admitted {
			t.Fatal("inbound admission rejected before reaching its limit")
		}
		releases = append(releases, release)
	}
	if _, admitted := service.acquireInboundAdmission(); admitted {
		t.Fatal("inbound admission exceeded its hard limit")
	}
	releases[0]()
	releases[0]()
	release, admitted := service.acquireInboundAdmission()
	if !admitted {
		t.Fatal("released inbound admission capacity was not reusable")
	}
	release()
	for _, release := range releases[1:] {
		release()
	}
}

type testStream struct {
	net.Conn
}

func (stream testStream) CloseWrite() error {
	return stream.Close()
}
