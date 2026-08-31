package protocol

import (
	"bytes"
	"fmt"
	"testing"
)

func BenchmarkControlFrameRoundTrip(b *testing.B) {
	payload := Heartbeat{Sequence: 1}
	b.ReportAllocs()
	for b.Loop() {
		var frame bytes.Buffer
		if err := WriteControl(&frame, MessagePing, payload); err != nil {
			b.Fatal(err)
		}
		if _, err := ReadControl(&frame); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkControlFrameWrite(b *testing.B) {
	for _, benchmarkCase := range controlBenchmarkCases() {
		b.Run(benchmarkCase.name, func(b *testing.B) {
			var frame bytes.Buffer
			b.ReportAllocs()
			for b.Loop() {
				frame.Reset()
				if err := WriteControl(&frame, benchmarkCase.messageType, benchmarkCase.payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkControlFrameRead(b *testing.B) {
	for _, benchmarkCase := range controlBenchmarkCases() {
		b.Run(benchmarkCase.name, func(b *testing.B) {
			var frame bytes.Buffer
			if err := WriteControl(&frame, benchmarkCase.messageType, benchmarkCase.payload); err != nil {
				b.Fatal(err)
			}
			frameBytes := bytes.Clone(frame.Bytes())
			reader := bytes.NewReader(frameBytes)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				reader.Reset(frameBytes)
				if _, err := ReadControl(reader); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkControlPayloadDecode(b *testing.B) {
	for _, benchmarkCase := range controlBenchmarkCases() {
		b.Run(benchmarkCase.name, func(b *testing.B) {
			var frame bytes.Buffer
			if err := WriteControl(&frame, benchmarkCase.messageType, benchmarkCase.payload); err != nil {
				b.Fatal(err)
			}
			envelope, err := ReadControl(&frame)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				destination := benchmarkCase.newDestination()
				if err := DecodePayload(envelope, destination); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

type controlBenchmarkCase struct {
	name           string
	messageType    MessageType
	payload        any
	newDestination func() any
}

func controlBenchmarkCases() []controlBenchmarkCase {
	declarations100 := benchmarkProxyDeclarations(100)
	declarations128 := benchmarkProxyDeclarations(128)
	return []controlBenchmarkCase{
		{
			name:           "Heartbeat",
			messageType:    MessagePing,
			payload:        Heartbeat{Sequence: 1},
			newDestination: func() any { return new(Heartbeat) },
		},
		{
			name:        "Sync100Proxies",
			messageType: MessageSyncConfiguration,
			payload: SyncConfiguration{
				Revision: 1, Proxies: declarations100, Forwards: []ForwardDeclaration{},
			},
			newDestination: func() any { return new(SyncConfiguration) },
		},
		{
			name:        "Sync128Proxies",
			messageType: MessageSyncConfiguration,
			payload: SyncConfiguration{
				Revision: 1, Proxies: declarations128, Forwards: []ForwardDeclaration{},
			},
			newDestination: func() any { return new(SyncConfiguration) },
		},
		{
			name:        "OpenLink",
			messageType: MessageOpenLink,
			payload: OpenLink{
				ProxyName: "benchmark-proxy", ProxyType: ProxyTypeTCP,
				BindingID: "benchmark-binding", LinkID: "benchmark-link",
				Ticket: "benchmark-ticket", ExpiresAtUnixMS: 1,
			},
			newDestination: func() any { return new(OpenLink) },
		},
		{
			name:        "BindLink",
			messageType: MessageBindLink,
			payload: BindLink{
				ClientID: "benchmark-client", SessionID: "benchmark-session",
				ProxyType: ProxyTypeTCP, BindingID: "benchmark-binding",
				LinkID: "benchmark-link", Ticket: "benchmark-ticket",
			},
			newDestination: func() any { return new(BindLink) },
		},
	}
}

func benchmarkProxyDeclarations(count int) []ProxyDeclaration {
	declarations := make([]ProxyDeclaration, count)
	for index := range declarations {
		declarations[index] = ProxyDeclaration{
			Name:       fmt.Sprintf("proxy-%04d", index),
			Type:       ProxyTypeTCP,
			RemotePort: uint16(20000 + index),
		}
	}
	return declarations
}
