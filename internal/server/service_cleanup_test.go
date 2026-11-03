package server

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
)

// trackedParentContext observes child cancellation without inspecting runtime internals.
// Its Done channel stays open so only the service can release its registrations.
type trackedParentContext struct {
	context.Context
	done          chan struct{}
	registrations atomic.Int64
}

func (parent *trackedParentContext) Done() <-chan struct{} { return parent.done }

func (parent *trackedParentContext) AfterFunc(func()) func() bool {
	parent.registrations.Add(1)
	var once sync.Once
	return func() bool {
		stopped := false
		once.Do(func() {
			parent.registrations.Add(-1)
			stopped = true
		})
		return stopped
	}
}

func TestStartupFailureReleasesSessionContext(t *testing.T) {
	parent := &trackedParentContext{Context: context.Background(), done: make(chan struct{})}
	configuration := config.DefaultServer()
	configuration.Transport.ListenAddress = "127.0.0.1:0"
	token := "startup-cleanup-test-token-with-at-least-32-bytes"
	configuration.Authentication.SharedToken = &token
	configuration.Proxies.HTTP.ListenAddress = "invalid-listen-address"
	service := NewService(logging.New("startup-cleanup-test"), configuration)
	err := service.Run(parent)
	if err == nil || !strings.Contains(err.Error(), "listen for HTTP proxy requests") {
		t.Fatalf("Run() = %v, want HTTP listener setup failure", err)
	}
	if remaining := parent.registrations.Load(); remaining != 0 {
		t.Fatalf("startup failure retained %d parent cancellation registrations", remaining)
	}
}
