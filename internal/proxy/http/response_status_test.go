package http

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"testing"
)

type upgradeResponseWriter struct {
	informationalResponseWriter
	connection net.Conn
}

func (writer *upgradeResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return writer.connection, bufio.NewReadWriter(bufio.NewReader(writer.connection), bufio.NewWriter(writer.connection)), nil
}

func TestResponseStatusTracksSuccessfulHijack(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	writer := &statusResponseWriter{ResponseWriter: &upgradeResponseWriter{connection: local}}
	connection, _, err := http.NewResponseController(writer).Hijack()
	if err != nil || connection != local || writer.statusCode != http.StatusSwitchingProtocols {
		t.Fatalf("successful Upgrade status = %d, error = %v", writer.statusCode, err)
	}
	unsupported := &statusResponseWriter{ResponseWriter: &informationalResponseWriter{}}
	if _, _, err := unsupported.Hijack(); !errors.Is(err, http.ErrNotSupported) || unsupported.statusCode != 0 {
		t.Fatalf("unsupported hijack status = %d, error = %v", unsupported.statusCode, err)
	}
}

type informationalResponseWriter struct {
	header   http.Header
	statuses []int
}

func (writer *informationalResponseWriter) Header() http.Header { return writer.header }
func (writer *informationalResponseWriter) WriteHeader(status int) {
	writer.statuses = append(writer.statuses, status)
}
func (writer *informationalResponseWriter) Write(body []byte) (int, error) { return len(body), nil }

func TestResponseStatusIgnoresInformationalHeaders(t *testing.T) {
	for _, final := range []int{http.StatusCreated, http.StatusSwitchingProtocols, 0} {
		underlying := &informationalResponseWriter{header: make(http.Header)}
		writer := &statusResponseWriter{ResponseWriter: underlying}
		writer.WriteHeader(http.StatusContinue)
		writer.WriteHeader(http.StatusEarlyHints)
		if writer.statusCode != 0 {
			t.Fatal("informational response recorded as final status")
		}
		expected := final
		if final == 0 {
			if _, err := writer.Write([]byte("body")); err != nil {
				t.Fatal(err)
			}
			expected = http.StatusOK
		} else {
			writer.WriteHeader(final)
		}
		if writer.statusCode != expected {
			t.Fatalf("status = %d, want %d", writer.statusCode, expected)
		}
		if len(underlying.statuses) < 2 || underlying.statuses[0] != 100 || underlying.statuses[1] != 103 {
			t.Fatal("informational responses were not forwarded")
		}
	}
}
