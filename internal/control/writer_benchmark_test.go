package control

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/acexy/portway/internal/protocol"
)

func BenchmarkUrgentControlWrite(b *testing.B) {
	b.Run("WithoutContention", func(b *testing.B) {
		for b.Loop() {
			connection, peer := net.Pipe()
			writer := NewWriter(connection)
			readResult := make(chan error, 1)
			go func() {
				_, err := protocol.ReadControl(peer)
				readResult <- err
			}()
			if err := writer.Write(protocol.MessageOpenLink, benchmarkOpenLink()); err != nil {
				b.Fatal(err)
			}
			if err := <-readResult; err != nil {
				b.Fatal(err)
			}
			connection.Close()
			peer.Close()
		}
	})

	b.Run("Behind800KiBFrame", func(b *testing.B) {
		largePayload := json.RawMessage(append(
			append([]byte{'"'}, bytes.Repeat([]byte{'x'}, 800*1024)...),
			'"',
		))
		for b.Loop() {
			connection, peer := net.Pipe()
			observed := &firstWriteObserver{Writer: connection, started: make(chan struct{})}
			writer := NewWriter(observed)
			largeResult := make(chan error, 1)
			go func() {
				largeResult <- writer.Write(protocol.MessageManagedConfigPrepare, largePayload)
			}()
			<-observed.started
			readResult := make(chan error, 1)
			go func() {
				for range 2 {
					if _, err := protocol.ReadControl(peer); err != nil {
						readResult <- err
						return
					}
				}
				readResult <- nil
			}()
			if err := writer.Write(protocol.MessageOpenLink, benchmarkOpenLink()); err != nil {
				b.Fatal(err)
			}
			if err := <-largeResult; err != nil {
				b.Fatal(err)
			}
			if err := <-readResult; err != nil {
				b.Fatal(err)
			}
			connection.Close()
			peer.Close()
		}
	})
}

type firstWriteObserver struct {
	io.Writer
	once    sync.Once
	started chan struct{}
}

func (observer *firstWriteObserver) Write(data []byte) (int, error) {
	observer.once.Do(func() { close(observer.started) })
	return observer.Writer.Write(data)
}

func benchmarkOpenLink() protocol.OpenLink {
	return protocol.OpenLink{
		LinkID: "benchmark-link", ProxyName: "benchmark-proxy",
		ProxyType: protocol.ProxyTypeTCP, BindingID: "benchmark-binding",
		Ticket: "benchmark-ticket", ExpiresAtUnixMS: 1,
	}
}
