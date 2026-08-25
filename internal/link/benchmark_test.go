package link

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/protocol"
)

func BenchmarkBrokerPendingLifecycle(b *testing.B) {
	ctx, cancelContext := context.WithCancel(context.Background())
	broker := NewBroker(ctx)
	var controlFrames bytes.Buffer
	target := Target{
		ClientID:  "benchmark-client",
		SessionID: "benchmark-session",
		ProxyName: "benchmark-proxy",
		ProxyType: protocol.ProxyTypeTCP,
		BindingID: "benchmark-binding",
		Writer:    control.NewWriter(&controlFrames),
	}
	b.Cleanup(func() {
		cancelContext()
		broker.Close()
	})

	b.ReportAllocs()
	for b.Loop() {
		controlFrames.Reset()
		linkID, err := broker.request(target, nil, nil, func(context.Context, string, net.Conn) error {
			return nil
		})
		if err != nil {
			b.Fatal(err)
		}
		broker.cancel(linkID, false, context.Canceled)
	}
}

func BenchmarkBrokerPendingLifecycleParallel(b *testing.B) {
	ctx, cancelContext := context.WithCancel(context.Background())
	broker := NewBroker(ctx)
	target := Target{
		ClientID:  "benchmark-client",
		SessionID: "benchmark-session",
		ProxyName: "benchmark-proxy",
		ProxyType: protocol.ProxyTypeTCP,
		BindingID: "benchmark-binding",
		Writer:    control.NewWriter(io.Discard),
	}
	b.Cleanup(func() {
		cancelContext()
		broker.Close()
	})

	b.ReportAllocs()
	b.RunParallel(func(parallel *testing.PB) {
		for parallel.Next() {
			linkID, err := broker.request(target, nil, nil, func(context.Context, string, net.Conn) error {
				return nil
			})
			if err != nil {
				b.Fatal(err)
			}
			broker.cancel(linkID, false, context.Canceled)
		}
	})
}

func BenchmarkBrokerBindLifecycle(b *testing.B) {
	ctx, cancelContext := context.WithCancel(context.Background())
	broker := NewBroker(ctx)
	var controlFrames bytes.Buffer
	target := Target{
		ClientID:  "benchmark-client",
		SessionID: "benchmark-session",
		ProxyName: "benchmark-proxy",
		ProxyType: protocol.ProxyTypeTCP,
		BindingID: "benchmark-binding",
		Writer:    control.NewWriter(&controlFrames),
	}
	b.Cleanup(func() {
		cancelContext()
		broker.Close()
	})

	bindResults := make(chan error, 1)
	handlerReady := make(chan struct{})
	releaseHandler := make(chan struct{})
	b.ReportAllocs()
	for b.Loop() {
		controlFrames.Reset()
		linkID, err := broker.request(target, nil, nil, func(context.Context, string, net.Conn) error {
			handlerReady <- struct{}{}
			<-releaseHandler
			return nil
		})
		if err != nil {
			b.Fatal(err)
		}
		envelope, err := protocol.ReadControl(&controlFrames)
		if err != nil {
			b.Fatal(err)
		}
		var openLink protocol.OpenLink
		if err := protocol.DecodePayload(envelope, &openLink); err != nil {
			b.Fatal(err)
		}
		if openLink.LinkID != linkID {
			b.Fatal("open link identifier mismatch")
		}

		serverData, clientData := net.Pipe()
		go func() {
			bindResults <- broker.Bind(context.Background(), serverData, protocol.BindLink{
				ClientID:  target.ClientID,
				SessionID: target.SessionID,
				ProxyType: target.ProxyType,
				BindingID: target.BindingID,
				LinkID:    openLink.LinkID,
				Ticket:    openLink.Ticket,
			}, authentication.Context{})
		}()
		bindEnvelope, err := protocol.ReadControl(clientData)
		if err != nil {
			clientData.Close()
			b.Fatal(err)
		}
		var bindResult protocol.BindResult
		if err := protocol.DecodePayload(bindEnvelope, &bindResult); err != nil {
			clientData.Close()
			b.Fatal(err)
		}
		if bindResult.Status != protocol.LinkStatusAccepted {
			clientData.Close()
			b.Fatalf("binding rejected: %+v", bindResult)
		}
		<-handlerReady
		releaseHandler <- struct{}{}
		if err := <-bindResults; err != nil {
			clientData.Close()
			b.Fatal(err)
		}
		clientData.Close()
	}
}
