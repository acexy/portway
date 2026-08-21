package quic

import (
	"context"
	"io"
	"testing"

	"github.com/acexy/portway/internal/protocol"
)

func BenchmarkQUICDataStreamLifecycle(b *testing.B) {
	certificateFile, keyFile := writeTestCertificate(b)
	ctx, cancel := context.WithCancel(b.Context())
	server, err := NewServer(ctx, ServerConfig{
		Address:     "127.0.0.1:0",
		CertFile:    certificateFile,
		KeyFile:     keyFile,
		Credentials: testCredentials(b, testToken),
	}, 8)
	if err != nil {
		b.Fatal(err)
	}
	client, err := NewClient(ClientConfig{
		Address:    server.listener.Addr().String(),
		ServerName: "localhost",
		CAFile:     certificateFile,
		Token:      testToken,
	})
	if err != nil {
		server.Close()
		b.Fatal(err)
	}
	session, err := client.Connect(ctx)
	if err != nil {
		server.Close()
		b.Fatal(err)
	}
	controlInbound, err := server.Accept(ctx)
	if err != nil {
		session.Close()
		server.Close()
		b.Fatal(err)
	}
	if controlInbound.Role != protocol.RoleControl {
		session.Close()
		server.Close()
		b.Fatalf("unexpected control role %d", controlInbound.Role)
	}
	b.Cleanup(func() {
		session.Close()
		server.Close()
		cancel()
	})

	payload := []byte{1}
	b.ReportAllocs()
	b.SetBytes(1)
	b.ResetTimer()
	for b.Loop() {
		clientStream, err := session.OpenDataStream(ctx)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := clientStream.Write(payload); err != nil {
			clientStream.Close()
			b.Fatal(err)
		}
		if err := clientStream.CloseWrite(); err != nil {
			clientStream.Close()
			b.Fatal(err)
		}
		inbound, err := server.Accept(ctx)
		if err != nil {
			clientStream.Close()
			b.Fatal(err)
		}
		if inbound.Role != protocol.RoleData {
			inbound.Stream.Close()
			clientStream.Close()
			b.Fatalf("unexpected data role %d", inbound.Role)
		}
		received, err := io.ReadAll(inbound.Stream)
		inbound.Stream.Close()
		clientStream.Close()
		if err != nil {
			b.Fatal(err)
		}
		if len(received) != 1 || received[0] != payload[0] {
			b.Fatalf("unexpected stream payload %v", received)
		}
	}
}
