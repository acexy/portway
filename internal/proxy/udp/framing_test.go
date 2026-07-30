package udp

import (
	"bytes"
	"errors"
	"testing"
)

func TestDatagramFrameRoundTrip(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("portway udp")} {
		var buffer bytes.Buffer
		if err := WriteDatagram(&buffer, payload, 64); err != nil {
			t.Fatalf("write datagram: %v", err)
		}
		actual, err := ReadDatagram(&buffer, 64)
		if err != nil {
			t.Fatalf("read datagram: %v", err)
		}
		if !bytes.Equal(actual, payload) {
			t.Fatalf("unexpected payload: %q", actual)
		}
	}
}

func TestDatagramFrameRejectsOversizedPayload(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteDatagram(&buffer, []byte("large"), 4); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("expected invalid frame error, got %v", err)
	}

	buffer.Write([]byte{0, 0, 0, 5})
	if _, err := ReadDatagram(&buffer, 4); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("expected invalid frame error, got %v", err)
	}
}
