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
	case 8192:
		return "8KiB"
	case 64 * 1024:
		return "64KiB"
	default:
		return "payload"
	}
}

func BenchmarkDatagramFrameWrite(b *testing.B) {
	for _, size := range []int{64, 1400, 8192} {
		b.Run(datagramSizeName(size), func(b *testing.B) {
			payload := make([]byte, size)
			b.Run("separate", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					if err := WriteDatagram(io.Discard, payload, size); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("buffered", func(b *testing.B) {
				buffer := make([]byte, frameHeaderSize+size)
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					if err := writeDatagramBuffer(io.Discard, payload, size, buffer); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkDatagramStreamWrite(b *testing.B) {
	for _, size := range []int{64, 1400, 8192} {
		b.Run(datagramSizeName(size), func(b *testing.B) {
			for _, buffered := range []bool{false, true} {
				name := "separate"
				if buffered {
					name = "buffered"
				}
				b.Run(name, func(b *testing.B) {
					writer, reader := net.Pipe()
					done := make(chan struct{})
					go func() {
						defer close(done)
						// Fit a complete frame so the benchmark does not introduce
						// an artificial read boundary at an 8 KiB payload.
						incoming := make([]byte, frameHeaderSize+size)
						for {
							if _, err := reader.Read(incoming); err != nil {
								return
							}
						}
					}()
					b.Cleanup(func() { writer.Close(); reader.Close(); <-done })
					payload := make([]byte, size)
					buffer := make([]byte, frameHeaderSize+size)
					b.ReportAllocs()
					b.SetBytes(int64(size))
					for b.Loop() {
						var err error
						if buffered {
							err = writeDatagramBuffer(writer, payload, size, buffer)
						} else {
							err = WriteDatagram(writer, payload, size)
						}
						if err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}
