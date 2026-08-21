package tcp

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
)

func BenchmarkTCPForward(b *testing.B) {
	for _, payloadSize := range []int{1024, 32 * 1024, 1024 * 1024} {
		b.Run(tcpPayloadSizeName(payloadSize), func(b *testing.B) {
			visitor, proxyLeft := net.Pipe()
			proxyRight, backend := net.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			forwardErrors := make(chan error, 1)
			go func() {
				forwardErrors <- Forward(ctx, proxyLeft, proxyRight)
			}()
			echoErrors := make(chan error, 1)
			go func() {
				buffer := make([]byte, payloadSize)
				for {
					if _, err := io.ReadFull(backend, buffer); err != nil {
						echoErrors <- err
						return
					}
					if _, err := backend.Write(buffer); err != nil {
						echoErrors <- err
						return
					}
				}
			}()
			b.Cleanup(func() {
				cancel()
				visitor.Close()
				backend.Close()
				<-forwardErrors
				<-echoErrors
			})

			payload := bytes.Repeat([]byte("p"), payloadSize)
			response := make([]byte, payloadSize)
			b.ReportAllocs()
			b.SetBytes(int64(payloadSize * 2))
			b.ResetTimer()
			for b.Loop() {
				if _, err := visitor.Write(payload); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(visitor, response); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func tcpPayloadSizeName(size int) string {
	switch size {
	case 1024:
		return "1KiB"
	case 32 * 1024:
		return "32KiB"
	case 1024 * 1024:
		return "1MiB"
	default:
		return "payload"
	}
}
