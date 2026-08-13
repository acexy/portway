package protocol

import (
	"bytes"
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
