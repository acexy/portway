package token

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/security/ipfilter"
)

func TestTCPServerRejectsDeniedSourceBeforeAuthentication(t *testing.T) {
	rulesPath := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(rulesPath, []byte("127.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sourceFilter, err := ipfilter.New(
		ctx,
		logging.New("tcp-filter-test"),
		rulesPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceFilter.Close()
	server, err := NewServer(
		ctx,
		"127.0.0.1:0",
		"test-token-with-at-least-32-random-bytes",
		8,
		sourceFilter,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	if _, err := DialToken(
		ctx,
		server.listener.Addr().String(),
		"test-token-with-at-least-32-random-bytes",
		protocol.RoleControl,
	); err == nil {
		t.Fatal("DialToken() succeeded for a denied source")
	}
}

func TestTokenHandshakeAndEncryptedExchange(t *testing.T) {
	t.Parallel()

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	type serverResult struct {
		connection net.Conn
		role       protocol.Role
		err        error
	}
	serverResults := make(chan serverResult, 1)
	go func() {
		connection, role, err := serverTokenHandshake(
			context.Background(),
			serverRaw,
			"test-token-with-at-least-32-random-bytes",
			nil,
		)
		serverResults <- serverResult{connection: connection, role: role, err: err}
	}()

	clientConnection, err := clientTokenHandshake(
		context.Background(),
		clientRaw,
		"test-token-with-at-least-32-random-bytes",
		protocol.RoleControl,
	)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	serverHandshake := <-serverResults
	if serverHandshake.err != nil {
		t.Fatalf("server handshake failed: %v", serverHandshake.err)
	}
	if serverHandshake.role != protocol.RoleControl {
		t.Fatalf("unexpected role: %v", serverHandshake.role)
	}

	message := []byte("encrypted control payload")
	writeErrors := make(chan error, 1)
	go func() {
		_, writeErr := clientConnection.Write(message)
		writeErrors <- writeErr
	}()

	received := make([]byte, len(message))
	if _, err := io.ReadFull(serverHandshake.connection, received); err != nil {
		t.Fatalf("read encrypted payload: %v", err)
	}
	if err := <-writeErrors; err != nil {
		t.Fatalf("write encrypted payload: %v", err)
	}
	if string(received) != string(message) {
		t.Fatalf("unexpected payload: %q", received)
	}
}

func TestTokenHandshakeRejectsMismatchedToken(t *testing.T) {
	t.Parallel()

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	serverErrors := make(chan error, 1)
	go func() {
		_, _, err := serverTokenHandshake(
			context.Background(),
			serverRaw,
			"server-token-with-at-least-32-random-bytes",
			nil,
		)
		serverErrors <- err
	}()

	_, err := clientTokenHandshake(
		context.Background(),
		clientRaw,
		"client-token-with-at-least-32-random-bytes",
		protocol.RoleControl,
	)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected authentication error, got %v", err)
	}
	clientRaw.Close()
	if serverErr := <-serverErrors; serverErr == nil {
		t.Fatal("server accepted a mismatched token")
	}
}

func TestTokenHandshakeRejectsDisallowedRoleBeforeProof(t *testing.T) {
	t.Parallel()

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	serverErrors := make(chan error, 1)
	go func() {
		_, _, err := serverTokenHandshake(
			context.Background(),
			serverRaw,
			"test-token-with-at-least-32-random-bytes",
			[]protocol.Role{protocol.RoleControl},
		)
		serverRaw.Close()
		serverErrors <- err
	}()

	_, clientErr := clientTokenHandshake(
		context.Background(),
		clientRaw,
		"test-token-with-at-least-32-random-bytes",
		protocol.RoleData,
	)
	if clientErr == nil {
		t.Fatal("client completed a handshake for a disallowed role")
	}
	if serverErr := <-serverErrors; !errors.Is(serverErr, ErrProtocol) {
		t.Fatalf("expected protocol error, got %v", serverErr)
	}
}

func TestSecureConnectionReportsRecordAuthenticationFailure(t *testing.T) {
	t.Parallel()

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	key := make([]byte, 32)
	connection, err := newSecureConnection(serverRaw, key, key)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		header := make([]byte, recordHeaderSize)
		binary.BigEndian.PutUint32(header[:4], uint32(connection.readAEAD.Overhead()))
		_, _ = clientRaw.Write(append(header, make([]byte, connection.readAEAD.Overhead())...))
	}()

	buffer := make([]byte, 1)
	_, err = connection.Read(buffer)
	if !errors.Is(err, ErrRecordAuthentication) {
		t.Fatalf("expected record authentication error, got %v", err)
	}
	if errors.Is(err, ErrAuthentication) {
		t.Fatal("record authentication failure was classified as token authentication failure")
	}
}
