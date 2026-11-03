package udp

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/link"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/security/ipfilter"
)

type associationParentContext struct {
	context.Context
	done     chan struct{}
	children atomic.Int64
}

func (parent *associationParentContext) Done() <-chan struct{} { return parent.done }
func (parent *associationParentContext) AfterFunc(func()) func() bool {
	parent.children.Add(1)
	var once sync.Once
	return func() bool {
		stopped := false
		once.Do(func() { parent.children.Add(-1); stopped = true })
		return stopped
	}
}

func TestSourceRegistrationRejectionReleasesCandidateContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(path, []byte("192.0.2.1/32\n"), 0600); err != nil {
		t.Fatal(err)
	}
	filter, err := ipfilter.New(context.Background(), logging.New("admission-test"), path)
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Close()
	parent := &associationParentContext{Context: context.Background(), done: make(chan struct{})}
	configuration := config.DefaultUDPConfig()
	limiter := NewLimiter(configuration)
	binding := &Binding{context: parent, configuration: configuration, limiter: limiter, filter: filter,
		associations: make(map[netip.AddrPort]*association), resolveTarget: func() (link.Target, error) {
			return link.Target{ClientID: "client", BindingName: "proxy"}, nil
		}}
	binding.HandleDatagram(netip.MustParseAddrPort("192.0.2.1:1234"), []byte("rejected"))
	if parent.children.Load() != 0 || len(binding.associations) != 0 || limiter.SnapshotStats().Associations != 0 {
		t.Fatal("source registration rejection retained candidate resources")
	}
}
