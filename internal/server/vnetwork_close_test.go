package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/session"
	"github.com/acexy/portway/internal/transport"
	quictransport "github.com/acexy/portway/internal/transport/quic"
	"github.com/acexy/portway/internal/transport/tcp/token"
)

// Exercise the real transports and the VNet notifier, without creating a TUN.
func TestVNetGracefulCloseOverTransports(t *testing.T) {
	for _, kind := range []transport.Type{transport.TypeTCP, transport.TypeQUIC} {
		t.Run(string(kind), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			secret := "test-token-with-at-least-32-random-bytes"
			snapshot, err := authentication.NewSnapshot([]authentication.Record{{
				Context: authentication.Context{Mode: authentication.ModeShared}, Token: secret,
			}})
			if err != nil {
				t.Fatal(err)
			}
			credentials := authentication.NewStore(snapshot)
			var listener transport.Server
			var dialer transport.Client
			switch kind {
			case transport.TypeTCP:
				address := reserveTCPAddress(t).String()
				listener, err = token.NewServer(ctx, address, credentials, 8)
				dialer = token.NewClient(address, secret)
			case transport.TypeQUIC:
				address := reserveUDPAddress(t).String()
				certificate, key := writeQUICServerCertificate(t)
				listener, err = quictransport.NewServer(ctx, quictransport.ServerConfig{
					Address: address, CertFile: certificate, KeyFile: key, Credentials: credentials,
				}, 8)
				if err == nil {
					dialer, err = quictransport.NewClient(quictransport.ClientConfig{
						Address: address, ServerName: "localhost", CAFile: certificate, Token: secret,
					})
				}
			}
			if listener != nil {
				defer listener.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			peer, err := dialer.Connect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			inbound, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer inbound.Stream.Close()
			deadline, _ := ctx.Deadline()
			if err := peer.ControlStream().SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := inbound.Stream.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			log := logging.New("close-test")
			runtime := newServerVNetRuntime(ctx, log, config.DefaultServer().VirtualNetwork, nil)
			defer runtime.Close()
			writer := control.NewWriter(inbound.Stream)
			runtime.attach("client-one", "session-one", inbound.Generation, inbound.Authentication, writer, true)
			service := &Service{clientRegistry: session.NewRegistry(), vnetRuntime: runtime}
			if _, _, _, err := service.clientRegistry.Register("client-one", "", "session-one", inbound.Stream, time.Now()); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				defer inbound.Stream.Close()
				closed, err := service.serveControlMessages(inbound.Stream, "client-one", "session-one",
					log, writer, []protocol.Capability{protocol.CapabilityVNetIPv4}, inbound.Authentication, false, nil)
				if err == nil && !closed {
					err = fmt.Errorf("session did not close gracefully")
				}
				if err == nil {
					err = finishControlSession(inbound.Stream)
				}
				result <- err
			}()
			if err := protocol.WriteControl(peer.ControlStream(), protocol.MessageCloseSession, protocol.CloseSession{
				SessionID: "session-one", Reason: protocol.CloseReasonClientShutdown,
			}); err != nil {
				t.Fatal(err)
			}
			envelope, err := protocol.ReadControl(peer.ControlStream())
			if err != nil {
				t.Fatalf("VNet cleanup lost close acknowledgment: %v", err)
			}
			var acknowledgment protocol.CloseAck
			if envelope.Type != protocol.MessageCloseAck {
				t.Fatalf("unexpected message: %s", envelope.Type)
			}
			if err := protocol.DecodePayload(envelope, &acknowledgment); err != nil || acknowledgment.SessionID != "session-one" {
				t.Fatalf("invalid close acknowledgment: %+v error=%v", acknowledgment, err)
			}
			if runtime.hasSession("client-one") {
				t.Fatal("acknowledgment preceded VNet session removal")
			}
			if _, created, _, err := service.clientRegistry.Register("client-one", "", "session-two", inbound.Stream, time.Now()); err != nil || !created {
				t.Fatalf("client identity not released before acknowledgment: %v", err)
			}
			_ = peer.Close()
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("server close did not finish")
			}
		})
	}
}
