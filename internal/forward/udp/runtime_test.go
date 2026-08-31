package udp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
)

func TestEndpointPreservesUDPAssociationDatagrams(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	configuration := config.DefaultUDPConfig()
	configuration.MaxDatagramSize = 64
	configuration.MaxQueuedDatagramsPerAssociation = 4
	endpoint, err := Listen(
		ctx, "127.0.0.1:0", "client", "forward", configuration, proxyudp.NewLimiter(configuration),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- endpoint.Serve(func(association *Association) {
			select {
			case payload := <-association.Packets:
				association.ReleaseQueue(len(payload))
				_ = association.Write(payload)
			case <-association.Context.Done():
			}
		})
	}()
	visitor, err := net.Dial("udp", endpoint.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer visitor.Close()
	if _, err := visitor.Write([]byte("datagram")); err != nil {
		t.Fatal(err)
	}
	if err := visitor.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 64)
	length, err := visitor.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	if string(response[:length]) != "datagram" {
		t.Fatalf("response = %q", response[:length])
	}
	endpoint.Close()
	select {
	case err := <-serveErrors:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestEndpointCloseCancelsAssociationHandler(t *testing.T) {
	configuration := config.DefaultUDPConfig()
	configuration.MaxDatagramSize = 64
	configuration.MaxQueuedDatagramsPerAssociation = 4
	endpoint, err := Listen(
		context.Background(), "127.0.0.1:0", "client", "forward", configuration,
		proxyudp.NewLimiter(configuration),
	)
	if err != nil {
		t.Fatal(err)
	}
	handlerStarted := make(chan struct{})
	handlerStopped := make(chan struct{})
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- endpoint.Serve(func(association *Association) {
			close(handlerStarted)
			<-association.Context.Done()
			close(handlerStopped)
		})
	}()
	visitor, err := net.Dial("udp", endpoint.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer visitor.Close()
	if _, err := visitor.Write([]byte("start")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("association handler did not start")
	}
	if err := endpoint.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	select {
	case <-handlerStopped:
	case <-time.After(time.Second):
		t.Fatal("association handler did not stop")
	}
	select {
	case err := <-serveErrors:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestEndpointExpiresIdleAssociationAndReleasesCapacity(t *testing.T) {
	configuration := config.DefaultUDPConfig()
	configuration.AssociationIdleTimeout = 20 * time.Millisecond
	configuration.MaxAssociations = 1
	configuration.MaxAssociationsPerClient = 1
	configuration.MaxAssociationsPerProxy = 1
	endpoint, err := Listen(
		context.Background(), "127.0.0.1:0", "client", "forward", configuration,
		proxyudp.NewLimiter(configuration),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	started := make(chan struct{}, 2)
	go func() {
		_ = endpoint.Serve(func(association *Association) {
			started <- struct{}{}
			<-association.Context.Done()
		})
	}()

	first, err := net.Dial("udp", endpoint.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_, _ = first.Write([]byte("first"))
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first association did not start")
	}

	deadline := time.Now().Add(time.Second)
	for endpoint.limiter.SnapshotStats().Associations != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if stats := endpoint.limiter.SnapshotStats(); stats.Associations != 0 {
		t.Fatalf("idle association was not released: %+v", stats)
	}

	second, err := net.Dial("udp", endpoint.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_, _ = second.Write([]byte("second"))
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("released capacity was not reusable")
	}
}
