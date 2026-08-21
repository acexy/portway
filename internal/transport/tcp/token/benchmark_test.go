package token

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	"github.com/acexy/portway/internal/protocol"
)

func BenchmarkTokenHandshake(b *testing.B) {
	const token = "benchmark-token-with-at-least-32-random-bytes"
	credentials := testAuthenticationStore(b, token)
	type handshakeResult struct {
		connection *secureConnection
		err        error
	}
	serverResults := make(chan handshakeResult, 1)
	b.ReportAllocs()
	for b.Loop() {
		clientRaw, serverRaw := net.Pipe()
		go func() {
			connection, _, err := serverTokenHandshake(
				context.Background(),
				serverRaw,
				credentials,
				nil,
			)
			serverResults <- handshakeResult{connection: connection, err: err}
		}()
		clientConnection, err := clientTokenHandshake(
			context.Background(),
			clientRaw,
			token,
			protocol.RoleData,
		)
		if err != nil {
			clientRaw.Close()
			serverRaw.Close()
			b.Fatal(err)
		}
		serverResult := <-serverResults
		if serverResult.err != nil {
			clientConnection.Close()
			b.Fatal(serverResult.err)
		}
		clientConnection.Close()
		serverResult.connection.Close()
	}
}

func BenchmarkSecureRecordRoundTrip(b *testing.B) {
	for _, payloadSize := range []int{1024, 32 * 1024, maxRecordPlaintext} {
		b.Run(payloadSizeName(payloadSize), func(b *testing.B) {
			clientRaw, serverRaw := net.Pipe()
			client, err := newSecureConnection(
				clientRaw,
				bytes.Repeat([]byte{1}, 32),
				bytes.Repeat([]byte{2}, 32),
			)
			if err != nil {
				b.Fatal(err)
			}
			server, err := newSecureConnection(
				serverRaw,
				bytes.Repeat([]byte{2}, 32),
				bytes.Repeat([]byte{1}, 32),
			)
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() {
				client.Close()
				server.Close()
			})

			echoErrors := make(chan error, 1)
			go func() {
				_, copyErr := io.Copy(server, server)
				echoErrors <- copyErr
			}()

			payload := bytes.Repeat([]byte("p"), payloadSize)
			response := make([]byte, payloadSize)
			b.ReportAllocs()
			b.SetBytes(int64(payloadSize * 2))
			b.ResetTimer()
			for b.Loop() {
				if _, err := client.Write(payload); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(client, response); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			client.Close()
			server.Close()
			<-echoErrors
		})
	}
}

func payloadSizeName(size int) string {
	switch size {
	case 1024:
		return "1KiB"
	case 32 * 1024:
		return "32KiB"
	case 64 * 1024:
		return "64KiB"
	default:
		return "payload"
	}
}
