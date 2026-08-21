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

func TestReadDatagramIntoReusesCallerBuffer(t *testing.T) {
	payload := []byte("portway udp")
	var framed bytes.Buffer
	if err := WriteDatagram(&framed, payload, 64); err != nil {
		t.Fatal(err)
	}
	storage := make([]byte, 64)
	actual, err := ReadDatagramInto(&framed, storage, 64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, payload) {
		t.Fatalf("unexpected payload: %q", actual)
	}
	if len(actual) > 0 && &actual[0] != &storage[0] {
		t.Fatal("datagram did not reuse caller-owned storage")
	}
}

func TestReadDatagramIntoRejectsInsufficientBuffer(t *testing.T) {
	var framed bytes.Buffer
	if err := WriteDatagram(&framed, []byte("large"), 64); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDatagramInto(&framed, make([]byte, 4), 64); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("expected invalid frame error, got %v", err)
	}
}
