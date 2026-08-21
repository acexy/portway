package udp

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func BenchmarkUDPDatagramForward(b *testing.B) {
	for _, payloadSize := range []int{64, 512, 1400, 64 * 1024} {
		b.Run(datagramSizeName(payloadSize), func(b *testing.B) {
			visitor, proxyStream := net.Pipe()
			proxyLocal, backend := net.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			forwardErrors := make(chan error, 1)
			go func() {
				forwardErrors <- Forward(ctx, proxyStream, proxyLocal, payloadSize, time.Second)
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

			payload := bytes.Repeat([]byte("d"), payloadSize)
			b.ReportAllocs()
			b.SetBytes(int64(payloadSize * 2))
			b.ResetTimer()
			for b.Loop() {
				if err := WriteDatagram(visitor, payload, payloadSize); err != nil {
					b.Fatal(err)
				}
				if _, err := ReadDatagram(visitor, payloadSize); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func datagramSizeName(size int) string {
	switch size {
	case 64:
		return "64B"
	case 512:
		return "512B"
	case 1400:
		return "1400B"
	case 64 * 1024:
		return "64KiB"
	default:
		return "payload"
	}
}
