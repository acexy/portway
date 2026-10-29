package quic

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/transport"
)

func newStreamCloseTestPair(t *testing.T) (transport.Stream, transport.Stream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	certificateFile, keyFile := writeTestCertificate(t)
	server, err := NewServer(ctx, ServerConfig{
		Address: "127.0.0.1:0", CertFile: certificateFile, KeyFile: keyFile,
		Credentials: testCredentials(t, testToken),
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	client, err := NewClient(ClientConfig{
		Address: server.listener.Addr().String(), ServerName: "localhost",
		CAFile: certificateFile, Token: testToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	if _, err := server.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	local, err := session.OpenDataStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := local.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// QUIC exposes a new stream to the peer only after its first write.
	if _, err := local.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	inbound, err := server.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbound.Stream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(inbound.Stream, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	return local, inbound.Stream
}

func TestDataStreamCloseInterruptsBlockedIO(t *testing.T) {
	local, peer := newStreamCloseTestPair(t)
	written := make(chan error, 1)
	read := make(chan error, 1)
	go func() {
		// Exceed the peer's maximum receive window so it cannot buffer all data.
		_, err := local.Write(make([]byte, 2*maxStreamReceiveWindow))
		written <- err
	}()
	go func() {
		_, err := local.Read(make([]byte, 1))
		read <- err
	}()
	if _, err := io.ReadFull(peer, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-written:
		t.Fatalf("large write finished before close: %v", err)
	default:
	}
	if err := local.Close(); err != nil {
		t.Fatal(err)
	}
	for _, result := range []<-chan error{written, read} {
		select {
		case err := <-result:
			if err == nil {
				t.Error("closed stream completed blocked I/O without an error")
			}
		case <-time.After(time.Second):
			t.Fatal("Close did not interrupt blocked stream I/O")
		}
	}
	if err := local.Close(); err != nil {
		t.Fatalf("repeated Close: %v", err)
	}
}

func TestDataStreamClosePreservesCompletedHalfClose(t *testing.T) {
	local, peer := newStreamCloseTestPair(t)
	payload := bytes.Repeat([]byte("response"), 4096)
	if _, err := local.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := local.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := local.Close(); err != nil {
		t.Fatal(err)
	}
	received, err := io.ReadAll(peer)
	if err != nil || !bytes.Equal(received, payload) {
		t.Fatalf("half-closed stream delivered %d bytes, error %v", len(received), err)
	}
}

func TestDataStreamConcurrentCloseAndHalfClose(t *testing.T) {
	local, _ := newStreamCloseTestPair(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		results <- local.Close()
	}()
	go func() {
		<-start
		results <- local.CloseWrite()
	}()
	close(start)
	for range 2 {
		select {
		case err := <-results:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("concurrent close returned unexpected error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent close did not finish")
		}
	}
}
