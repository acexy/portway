package compression

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestStreamRoundTripAndHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverResult := make(chan error, 1)
	go func() {
		connection, acceptError := listener.Accept()
		if acceptError != nil {
			serverResult <- acceptError
			return
		}
		stream, streamError := NewStream(connection, AlgorithmZstd)
		if streamError != nil {
			connection.Close()
			serverResult <- streamError
			return
		}
		defer stream.Close()
		request, readError := io.ReadAll(stream)
		if readError != nil {
			serverResult <- readError
			return
		}
		if !bytes.Equal(request, bytes.Repeat([]byte("compressible-request-"), 256)) {
			serverResult <- io.ErrUnexpectedEOF
			return
		}
		if _, writeError := stream.Write([]byte("response")); writeError != nil {
			serverResult <- writeError
			return
		}
		serverResult <- stream.CloseWrite()
	}()

	connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := NewStream(connection, AlgorithmZstd)
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}
	defer stream.Close()
	request := bytes.Repeat([]byte("compressible-request-"), 256)
	if _, err := stream.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response" {
		t.Fatalf("response = %q", response)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestNewStreamRejectsUnsupportedAlgorithm(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if _, err := NewStream(left, Algorithm("unknown")); err == nil {
		t.Fatal("unsupported compression algorithm was accepted")
	}
}
