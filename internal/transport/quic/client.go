package quic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"

	quicgo "github.com/quic-go/quic-go"

	"github.com/acexy/portway/internal/transport"
)

var _ transport.Client = (*Client)(nil)
var _ transport.ClientSession = (*clientSession)(nil)

// ClientConfig contains the QUIC client transport settings.
type ClientConfig struct {
	Address    string
	ServerName string
	CAFile     string
	Token      string
}

// Client establishes Token-authenticated QUIC transport sessions.
type Client struct {
	configuration  ClientConfig
	tlsConfig      *tls.Config
	nextGeneration atomic.Uint64
}

// NewClient validates TLS trust settings and creates a QUIC transport client.
func NewClient(configuration ClientConfig) (*Client, error) {
	tlsConfig, err := newClientTLSConfig(configuration.ServerName, configuration.CAFile)
	if err != nil {
		return nil, err
	}
	return &Client{
		configuration: configuration,
		tlsConfig:     tlsConfig,
	}, nil
}

// Connect establishes one QUIC connection and authenticates its control stream.
func (client *Client) Connect(ctx context.Context) (transport.ClientSession, error) {
	generation := transport.Generation(client.nextGeneration.Add(1))
	connection, err := quicgo.DialAddr(
		ctx,
		client.configuration.Address,
		client.tlsConfig.Clone(),
		defaultQUICConfig(),
	)
	if err != nil {
		dialError := fmt.Errorf(
			"dial QUIC server %q: %w",
			client.configuration.Address,
			err,
		)
		return nil, classifyDialError(dialError)
	}
	controlStream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		connection.CloseWithError(applicationErrorProtocol, "open control stream")
		return nil, fmt.Errorf("open QUIC control stream: %w", err)
	}
	if err := authenticateClient(ctx, controlStream, client.configuration.Token); err != nil {
		errorCode := applicationErrorProtocol
		if errors.Is(err, transport.ErrAuthentication) {
			errorCode = applicationErrorAuth
		}
		connection.CloseWithError(errorCode, "QUIC authentication failed")
		return nil, err
	}
	return &clientSession{
		connection:   connection,
		control:      newStream(controlStream, connection, true),
		connectionID: transport.ConnectionID(fmt.Sprintf("quic-client-%d", generation)),
		generation:   generation,
	}, nil
}

func classifyDialError(err error) error {
	var certificateError *tls.CertificateVerificationError
	if errors.As(err, &certificateError) {
		return transport.Permanent(err)
	}

	var versionError *quicgo.VersionNegotiationError
	if errors.As(err, &versionError) {
		return transport.Permanent(err)
	}

	var quicTransportError *quicgo.TransportError
	if !errors.As(err, &quicTransportError) {
		return err
	}
	if quicTransportError.ErrorCode >= 0x100 {
		// QUIC maps TLS alerts, including certificate and ALPN failures, to
		// CRYPTO_ERROR codes in the range 0x100-0x1ff.
		return transport.Permanent(err)
	}
	switch quicTransportError.ErrorCode {
	case quicgo.FrameEncodingError,
		quicgo.TransportParameterError,
		quicgo.ProtocolViolation:
		return transport.Permanent(err)
	default:
		return err
	}
}

type clientSession struct {
	connection   *quicgo.Conn
	control      transport.Stream
	connectionID transport.ConnectionID
	generation   transport.Generation
	mutex        sync.Mutex
	closed       bool
}

func (session *clientSession) ControlStream() transport.Stream {
	return session.control
}

func (session *clientSession) OpenDataStream(ctx context.Context) (transport.Stream, error) {
	session.mutex.Lock()
	closed := session.closed
	session.mutex.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	quicStream, err := session.connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open QUIC data stream: %w", err)
	}
	return newStream(quicStream, session.connection, false), nil
}

func (session *clientSession) ConnectionID() transport.ConnectionID {
	return session.connectionID
}

func (session *clientSession) Generation() transport.Generation {
	return session.generation
}

func (session *clientSession) Close() error {
	session.mutex.Lock()
	if session.closed {
		session.mutex.Unlock()
		return nil
	}
	session.closed = true
	session.mutex.Unlock()
	return session.control.Close()
}

func newClientTLSConfig(serverName string, caFile string) (*tls.Config, error) {
	var rootCertificates *x509.CertPool
	if caFile != "" {
		certificateData, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read QUIC CA file: %w", err)
		}
		rootCertificates, err = x509.SystemCertPool()
		if err != nil {
			rootCertificates = x509.NewCertPool()
		}
		if !rootCertificates.AppendCertsFromPEM(certificateData) {
			return nil, errors.New("QUIC CA file contains no valid certificates")
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		RootCAs:    rootCertificates,
		NextProtos: []string{alpn},
	}, nil
}
