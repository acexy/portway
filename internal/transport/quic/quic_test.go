package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/security/ipfilter"
	"github.com/acexy/portway/internal/transport"
)

const testToken = "test-token-with-at-least-32-random-bytes"

func testCredentials(t testing.TB, token string) *authentication.Store {
	t.Helper()
	snapshot, err := authentication.NewSnapshot([]authentication.Record{{
		Context: authentication.Context{Mode: authentication.ModeShared},
		Token:   token,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return authentication.NewStore(snapshot)
}

func TestQUICServerRevokesAuthenticatedConnection(t *testing.T) {
	certificateFile, keyFile := writeTestCertificate(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	credentials := testCredentials(t, testToken)
	server, err := NewServer(ctx, ServerConfig{
		Address:     "127.0.0.1:0",
		CertFile:    certificateFile,
		KeyFile:     keyFile,
		Credentials: credentials,
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewClient(ClientConfig{
		Address:    server.listener.Addr().String(),
		ServerName: "localhost",
		CAFile:     certificateFile,
		Token:      testToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientSession, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	inbound, err := server.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server.RevokeAuthentication([]authentication.Context{inbound.Authentication})

	buffer := make([]byte, 1)
	if err := clientSession.ControlStream().SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := clientSession.ControlStream().Read(buffer); err == nil {
		t.Fatal("revoked QUIC connection remained readable")
	}
	if stream, err := clientSession.OpenDataStream(ctx); err == nil {
		stream.Close()
		t.Fatal("revoked QUIC connection opened a new stream")
	}
}

func TestQUICServerRejectsUnknownSelectorWithDummyToken(t *testing.T) {
	certificateFile, keyFile := writeTestCertificate(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, err := NewServer(ctx, ServerConfig{
		Address:     "127.0.0.1:0",
		CertFile:    certificateFile,
		KeyFile:     keyFile,
		Credentials: testCredentials(t, testToken),
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewClient(ClientConfig{
		Address:    server.listener.Addr().String(),
		ServerName: "localhost",
		CAFile:     certificateFile,
		Token:      string(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Connect(ctx); err == nil {
		t.Fatal("unknown selector authenticated with the dummy Token")
	}
}

func TestQUICServerRejectsDeniedSource(t *testing.T) {
	certificateFile, keyFile := writeTestCertificate(t)
	rulesPath := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(rulesPath, []byte("127.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sourceFilter, err := ipfilter.New(
		ctx,
		logging.New("quic-filter-test"),
		rulesPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceFilter.Close()
	server, err := NewServer(ctx, ServerConfig{
		Address:     "127.0.0.1:0",
		CertFile:    certificateFile,
		KeyFile:     keyFile,
		Credentials: testCredentials(t, testToken),
	}, 8, sourceFilter)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewClient(ClientConfig{
		Address:    server.listener.Addr().String(),
		ServerName: "localhost",
		CAFile:     certificateFile,
		Token:      testToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Connect(ctx); err == nil {
		t.Fatal("Connect() succeeded for a denied source")
	}
}

func TestQUICControlAndDataStreams(t *testing.T) {
	certificateFile, keyFile := writeTestCertificate(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server, err := NewServer(ctx, ServerConfig{
		Address:     "127.0.0.1:0",
		CertFile:    certificateFile,
		KeyFile:     keyFile,
		Credentials: testCredentials(t, testToken),
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := NewClient(ClientConfig{
		Address:    server.listener.Addr().String(),
		ServerName: "localhost",
		CAFile:     certificateFile,
		Token:      testToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("connect QUIC client: %v", err)
	}
	defer session.Close()

	controlInbound, err := server.Accept(ctx)
	if err != nil {
		t.Fatalf("accept QUIC control stream: %v", err)
	}
	if controlInbound.Role != protocol.RoleControl {
		t.Fatalf("unexpected control role %d", controlInbound.Role)
	}

	clientDataStream, err := session.OpenDataStream(ctx)
	if err != nil {
		t.Fatalf("open QUIC data stream: %v", err)
	}
	defer clientDataStream.Close()
	request := []byte("request over QUIC stream")
	if _, err := clientDataStream.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := clientDataStream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	dataInbound, err := server.Accept(ctx)
	if err != nil {
		t.Fatalf("accept QUIC data stream: %v", err)
	}
	defer dataInbound.Stream.Close()
	if dataInbound.Role != protocol.RoleData {
		t.Fatalf("unexpected data role %d", dataInbound.Role)
	}
	if dataInbound.ConnectionID != controlInbound.ConnectionID ||
		dataInbound.Generation != controlInbound.Generation {
		t.Fatal("QUIC streams from one connection did not share identity")
	}

	receivedRequest, err := io.ReadAll(dataInbound.Stream)
	if err != nil {
		t.Fatalf("read request after QUIC FIN: %v", err)
	}
	if string(receivedRequest) != string(request) {
		t.Fatalf("unexpected request %q", receivedRequest)
	}

	response := []byte("response over QUIC stream")
	if _, err := dataInbound.Stream.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := dataInbound.Stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	receivedResponse, err := io.ReadAll(clientDataStream)
	if err != nil {
		t.Fatalf("read response after QUIC FIN: %v", err)
	}
	if string(receivedResponse) != string(response) {
		t.Fatalf("unexpected response %q", receivedResponse)
	}
}

func TestQUICRejectsMismatchedToken(t *testing.T) {
	certificateFile, keyFile := writeTestCertificate(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := NewServer(ctx, ServerConfig{
		Address:     "127.0.0.1:0",
		CertFile:    certificateFile,
		KeyFile:     keyFile,
		Credentials: testCredentials(t, testToken),
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewClient(ClientConfig{
		Address:    server.listener.Addr().String(),
		ServerName: "localhost",
		CAFile:     certificateFile,
		Token:      "different-token-with-at-least-32-random-bytes",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Connect(ctx)
	if !errors.Is(err, transport.ErrAuthentication) {
		t.Fatalf("expected authentication error, got %v", err)
	}
}

func TestQUICConcurrentDataStreamsShareGeneration(t *testing.T) {
	certificateFile, keyFile := writeTestCertificate(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := NewServer(ctx, ServerConfig{
		Address:     "127.0.0.1:0",
		CertFile:    certificateFile,
		KeyFile:     keyFile,
		Credentials: testCredentials(t, testToken),
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewClient(ClientConfig{
		Address:    server.listener.Addr().String(),
		ServerName: "localhost",
		CAFile:     certificateFile,
		Token:      testToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	controlInbound, err := server.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}

	const streamCount = 16
	errorsChannel := make(chan error, streamCount)
	var waitGroup sync.WaitGroup
	for index := range streamCount {
		waitGroup.Add(1)
		go func(value byte) {
			defer waitGroup.Done()
			dataStream, openError := session.OpenDataStream(ctx)
			if openError != nil {
				errorsChannel <- openError
				return
			}
			defer dataStream.Close()
			if _, writeError := dataStream.Write([]byte{value}); writeError != nil {
				errorsChannel <- writeError
				return
			}
			if closeError := dataStream.CloseWrite(); closeError != nil {
				errorsChannel <- closeError
			}
		}(byte(index))
	}
	for range streamCount {
		inbound, acceptError := server.Accept(ctx)
		if acceptError != nil {
			t.Fatal(acceptError)
		}
		if inbound.Role != protocol.RoleData ||
			inbound.ConnectionID != controlInbound.ConnectionID ||
			inbound.Generation != controlInbound.Generation {
			t.Fatal("concurrent QUIC stream identity mismatch")
		}
		payload, readError := io.ReadAll(inbound.Stream)
		inbound.Stream.Close()
		if readError != nil {
			t.Fatal(readError)
		}
		if len(payload) != 1 {
			t.Fatalf("unexpected concurrent stream payload length %d", len(payload))
		}
	}
	waitGroup.Wait()
	close(errorsChannel)
	for streamError := range errorsChannel {
		if streamError != nil {
			t.Fatal(streamError)
		}
	}
}

func TestQUICReconnectUsesNewGeneration(t *testing.T) {
	certificateFile, keyFile := writeTestCertificate(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := NewServer(ctx, ServerConfig{
		Address:     "127.0.0.1:0",
		CertFile:    certificateFile,
		KeyFile:     keyFile,
		Credentials: testCredentials(t, testToken),
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewClient(ClientConfig{
		Address:    server.listener.Addr().String(),
		ServerName: "localhost",
		CAFile:     certificateFile,
		Token:      testToken,
	})
	if err != nil {
		t.Fatal(err)
	}

	firstSession, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	firstInbound, err := server.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	firstSession.Close()

	secondSession, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer secondSession.Close()
	secondInbound, err := server.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if secondSession.Generation() <= firstSession.Generation() ||
		secondInbound.Generation <= firstInbound.Generation ||
		secondInbound.ConnectionID == firstInbound.ConnectionID {
		t.Fatal("QUIC reconnect reused an old connection generation")
	}
}

func TestQUICRejectsUnexpectedServerName(t *testing.T) {
	certificateFile, keyFile := writeTestCertificate(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := NewServer(ctx, ServerConfig{
		Address:     "127.0.0.1:0",
		CertFile:    certificateFile,
		KeyFile:     keyFile,
		Credentials: testCredentials(t, testToken),
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewClient(ClientConfig{
		Address:    server.listener.Addr().String(),
		ServerName: "unexpected.example.com",
		CAFile:     certificateFile,
		Token:      testToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Connect(ctx); err == nil {
		t.Fatal("QUIC client accepted a certificate for a different server name")
	} else if !transport.IsPermanent(err) {
		t.Fatalf("certificate name error = %v, want permanent failure", err)
	}
}

func TestClassifyDialError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		err       error
		permanent bool
	}{
		{
			name:      "version negotiation",
			err:       &quicgo.VersionNegotiationError{},
			permanent: true,
		},
		{
			name: "TLS alert",
			err: &quicgo.TransportError{
				ErrorCode: 0x178,
			},
			permanent: true,
		},
		{
			name: "transport protocol violation",
			err: &quicgo.TransportError{
				ErrorCode: quicgo.ProtocolViolation,
			},
			permanent: true,
		},
		{
			name:      "handshake timeout",
			err:       &quicgo.HandshakeTimeoutError{},
			permanent: false,
		},
		{
			name:      "network failure",
			err:       errors.New("network unavailable"),
			permanent: false,
		},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			classified := classifyDialError(testCase.err)
			if actual := transport.IsPermanent(classified); actual != testCase.permanent {
				t.Fatalf(
					"IsPermanent(classifyDialError(%v)) = %t, want %t",
					testCase.err,
					actual,
					testCase.permanent,
				)
			}
		})
	}
}

func writeTestCertificate(t testing.TB) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificateFile := filepath.Join(t.TempDir(), "server.crt")
	keyFile := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateDER,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificateFile, keyFile
}
