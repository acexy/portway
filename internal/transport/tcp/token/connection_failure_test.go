package token

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
)

type failingRecordConnection struct {
	net.Conn
	writes    int
	failAfter int
	closed    bool
}

type recordReadConnection struct {
	failingRecordConnection
	reader io.Reader
	reads  int
}

func (connection *recordReadConnection) Read(payload []byte) (int, error) {
	connection.reads++
	return connection.reader.Read(payload)
}

func TestSecureConnectionReadFailureIsTerminal(t *testing.T) {
	header := make([]byte, recordHeaderSize)
	binary.BigEndian.PutUint32(header[:4], 16)
	invalidSequence := bytes.Clone(header)
	binary.BigEndian.PutUint64(invalidSequence[4:], 1)
	invalidLength := make([]byte, recordHeaderSize)
	for _, test := range []struct {
		name    string
		payload []byte
		want    error
	}{
		{"partial_header", header[:3], io.ErrUnexpectedEOF},
		{"missing_ciphertext", header, io.ErrUnexpectedEOF},
		{"partial_ciphertext", append(bytes.Clone(header), 0), io.ErrUnexpectedEOF},
		{"invalid_sequence", invalidSequence, ErrProtocol},
		{"invalid_length", invalidLength, ErrProtocol},
		{"invalid_authentication", append(bytes.Clone(header), make([]byte, 16)...), ErrRecordAuthentication},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := &recordReadConnection{reader: bytes.NewReader(test.payload)}
			key := make([]byte, 32)
			connection, err := newSecureConnection(raw, key, key)
			if err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 1)
			if count, err := connection.Read(buffer); count != 0 || !errors.Is(err, test.want) {
				t.Fatalf("Read() = %d, %v, want %v", count, err, test.want)
			}
			reads := raw.reads
			if count, err := connection.Read(buffer); count != 0 || !errors.Is(err, test.want) {
				t.Errorf("retry Read() = %d, %v, want %v", count, err, test.want)
			}
			if !raw.closed || raw.reads != reads {
				t.Errorf("terminal failure: closed = %v, extra reads = %d", raw.closed, raw.reads-reads)
			}
		})
	}
}

type recordReadTimeout struct{}

func (recordReadTimeout) Read([]byte) (int, error) {
	return 0, os.ErrDeadlineExceeded
}

func TestSecureConnectionPartialReadTimeoutIsTerminal(t *testing.T) {
	header := make([]byte, recordHeaderSize)
	binary.BigEndian.PutUint32(header[:4], 16)
	for _, prefix := range [][]byte{header[:3], header, append(bytes.Clone(header), 0)} {
		raw := &recordReadConnection{
			reader: io.MultiReader(bytes.NewReader(prefix), recordReadTimeout{}),
		}
		key := make([]byte, 32)
		connection, err := newSecureConnection(raw, key, key)
		if err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 1)
		if _, err := connection.Read(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("prefix %d: Read() = %v", len(prefix), err)
		}
		reads := raw.reads
		if _, err := connection.Read(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("prefix %d: retry Read() = %v", len(prefix), err)
		}
		if !raw.closed || raw.reads != reads {
			t.Errorf("prefix %d: partial timeout did not terminate reads", len(prefix))
		}
	}
}

func TestSecureConnectionBoundaryReadFailurePreservesConnection(t *testing.T) {
	for _, test := range []struct {
		name   string
		reader io.Reader
		want   error
	}{
		{"eof", bytes.NewReader(nil), io.EOF},
		{"timeout", recordReadTimeout{}, os.ErrDeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := &recordReadConnection{
				failingRecordConnection: failingRecordConnection{failAfter: 1},
				reader:                  test.reader,
			}
			key := make([]byte, 32)
			connection, err := newSecureConnection(raw, key, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Read(make([]byte, 1)); !errors.Is(err, test.want) {
				t.Fatalf("Read() = %v, want %v", err, test.want)
			}
			if raw.closed {
				t.Fatal("record-boundary read failure closed the write direction")
			}
			if _, err := connection.Write([]byte("response")); err != nil {
				t.Fatalf("Write() after boundary read failure: %v", err)
			}
			if test.want == io.EOF {
				return
			}
			header := make([]byte, recordHeaderSize)
			binary.BigEndian.PutUint32(header[:4], 17)
			nonce := recordNonce(0)
			frame := connection.readAEAD.Seal(header, nonce[:], []byte("x"), header)
			raw.reader = bytes.NewReader(frame)
			buffer := make([]byte, 1)
			if count, err := connection.Read(buffer); count != 1 || err != nil || buffer[0] != 'x' {
				t.Fatalf("Read() after boundary retry = %d, %v, %q", count, err, buffer)
			}
		})
	}
}

func (connection *failingRecordConnection) Write(payload []byte) (int, error) {
	connection.writes++
	if connection.writes > connection.failAfter {
		return len(payload) / 2, os.ErrDeadlineExceeded
	}
	return len(payload), nil
}

func (connection *failingRecordConnection) Close() error {
	connection.closed = true
	return nil
}

func TestSecureConnectionWriteFailureIsTerminal(t *testing.T) {
	for _, completeRecords := range []int{0, 1} {
		name := "first_record"
		if completeRecords > 0 {
			name = "after_complete_record"
		}
		t.Run(name, func(t *testing.T) {
			raw := &failingRecordConnection{failAfter: completeRecords}
			key := make([]byte, 32)
			connection, err := newSecureConnection(raw, key, key)
			if err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, completeRecords*maxRecordPlaintext+32)
			written, err := connection.Write(payload)
			if written != completeRecords*maxRecordPlaintext || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Write() = %d, %v", written, err)
			}
			ciphertext := bytes.Clone(connection.writeBuffer)
			written, err = connection.Write([]byte("different plaintext after failure"))
			if written != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("retry Write() = %d, %v", written, err)
			}
			if raw.writes != completeRecords+1 || !bytes.Equal(ciphertext, connection.writeBuffer) {
				t.Error("retry encrypted or sent another record after failure")
			}
			if !raw.closed {
				t.Error("failed record did not close the underlying connection")
			}
			if err := connection.CloseWrite(); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("CloseWrite() = %v, want original failure", err)
			}
		})
	}
}
