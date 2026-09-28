package udp

import (
	"bytes"
	"errors"
	"io"
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

type datagramCountingWriter struct {
	bytes.Buffer
	writes int
	limit  int
}

func (writer *datagramCountingWriter) Write(payload []byte) (int, error) {
	writer.writes++
	if writer.limit > 0 && len(payload) > writer.limit {
		payload = payload[:writer.limit]
	}
	return writer.Buffer.Write(payload)
}

func TestBufferedDatagramWritePreservesFramesAndShortWrites(t *testing.T) {
	for _, limit := range []int{0, 2} {
		writer := &datagramCountingWriter{limit: limit}
		buffer := make([]byte, frameHeaderSize+64)
		for _, payload := range [][]byte{nil, []byte("first"), []byte("second")} {
			before := writer.writes
			if err := writeDatagramBuffer(writer, payload, 64, buffer); err != nil {
				t.Fatal(err)
			}
			if limit == 0 && writer.writes-before != 1 {
				t.Fatal("frame was split across writes")
			}
		}
		for _, expected := range []string{"", "first", "second"} {
			payload, err := ReadDatagram(writer, 64)
			if err != nil || string(payload) != expected {
				t.Fatalf("payload = %q, want %q: %v", payload, expected, err)
			}
		}
		if err := writeDatagramBuffer(writer, make([]byte, 65), 64, buffer); !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("oversized frame accepted: %v", err)
		}
	}
}

type stalledDatagramWriter struct{}

func (stalledDatagramWriter) Write([]byte) (int, error) { return 0, nil }

func TestBufferedDatagramWriteRejectsNoProgress(t *testing.T) {
	if err := writeDatagramBuffer(stalledDatagramWriter{}, nil, 64, nil); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("non-progressing writer error = %v", err)
	}
}

func TestDatagramWriterCoalescesAndReusesStorage(t *testing.T) {
	output := &datagramCountingWriter{}
	writer := NewDatagramWriter(output, 64)
	for _, payload := range [][]byte{nil, []byte("one"), []byte("two")} {
		if err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	if output.writes != 3 {
		t.Fatalf("three frames used %d writes", output.writes)
	}
	for _, expected := range []string{"", "one", "two"} {
		payload, err := ReadDatagram(output, 64)
		if err != nil || string(payload) != expected {
			t.Fatalf("frame = %q, want %q: %v", payload, expected, err)
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
