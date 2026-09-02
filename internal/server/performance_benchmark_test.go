package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	toolkitlogger "github.com/acexy/golang-toolkit/logger"

	"github.com/acexy/portway/internal/client"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

const benchmarkToken = "benchmark-token-with-at-least-32-random-bytes"

type benchmarkServices struct {
	cancelClient context.CancelFunc
	cancelServer context.CancelFunc
	clientErrors chan error
	serverErrors chan error
}

func BenchmarkTCPLinkEstablishmentEndToEnd(b *testing.B) {
	disableBenchmarkLogging()
	for _, transportType := range []transport.Type{transport.TypeTCP, transport.TypeQUIC} {
		b.Run(string(transportType), func(b *testing.B) {
			echoListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			echoContext, cancelEcho := context.WithCancel(context.Background())
			go runEchoServer(echoContext, echoListener)
			b.Cleanup(func() {
				cancelEcho()
				echoListener.Close()
			})

			proxyAddress := reserveTCPAddress(b)
			serverConfiguration, clientConfiguration := benchmarkTransportConfigurations(b, transportType)
			serverConfiguration.Proxies.BindIP = "127.0.0.1"
			clientConfiguration.Authentication.ClientID = "benchmark-link-" + string(transportType)
			clientConfiguration.Proxies = []config.ProxyConfig{{
				Name: "echo", Type: "tcp",
				Local: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(echoListener.Addr().(*net.TCPAddr).Port)},
				Public: config.ProxyPublicConfig{Port: uint16(proxyAddress.Port)},
			}}
			startBenchmarkServices(b, serverConfiguration, clientConfiguration)

			var response [1]byte
			warmLinkEstablishment(b, proxyAddress.String(), response[:])

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				visitor, err := net.DialTimeout("tcp", proxyAddress.String(), 10*time.Second)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := visitor.Write([]byte{1}); err != nil {
					visitor.Close()
					b.Fatal(err)
				}
				if _, err := io.ReadFull(visitor, response[:]); err != nil {
					visitor.Close()
					b.Fatal(err)
				}
				closeBenchmarkVisitor(b, visitor)
			}
		})
	}
}

func warmLinkEstablishment(b *testing.B, address string, response []byte) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		visitor, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			if _, err = visitor.Write([]byte{1}); err == nil {
				_, err = io.ReadFull(visitor, response)
			}
			visitor.Close()
			if err == nil {
				return
			}
		}
		if time.Now().After(deadline) {
			b.Fatalf("warm link establishment: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func closeBenchmarkVisitor(b *testing.B, visitor net.Conn) {
	tcpConnection, ok := visitor.(*net.TCPConn)
	if !ok {
		visitor.Close()
		b.Fatal("benchmark visitor is not a TCP connection")
	}
	if err := tcpConnection.CloseWrite(); err != nil {
		visitor.Close()
		b.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, visitor); err != nil {
		visitor.Close()
		b.Fatal(err)
	}
	if err := visitor.Close(); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkTCPProxyEndToEnd(b *testing.B) {
	disableBenchmarkLogging()
	for _, transportType := range []transport.Type{transport.TypeTCP, transport.TypeQUIC} {
		b.Run(string(transportType), func(b *testing.B) {
			echoListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			echoContext, cancelEcho := context.WithCancel(context.Background())
			go runEchoServer(echoContext, echoListener)
			b.Cleanup(func() {
				cancelEcho()
				echoListener.Close()
			})

			proxyAddress := reserveTCPAddress(b)
			serverConfiguration, clientConfiguration := benchmarkTransportConfigurations(b, transportType)
			serverConfiguration.Proxies.BindIP = "127.0.0.1"
			clientConfiguration.Authentication.ClientID = "benchmark-tcp-" + string(transportType)
			clientConfiguration.Proxies = []config.ProxyConfig{{
				Name: "echo", Type: "tcp",
				Local: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(echoListener.Addr().(*net.TCPAddr).Port)},
				Public: config.ProxyPublicConfig{Port: uint16(proxyAddress.Port)},
			}}
			startBenchmarkServices(b, serverConfiguration, clientConfiguration)

			for _, payloadSize := range []int{1024, 32 * 1024, 1024 * 1024} {
				b.Run(benchmarkPayloadName(payloadSize), func(b *testing.B) {
					visitor := dialWithRetry(b, proxyAddress.String(), 10*time.Second)
					b.Cleanup(func() { visitor.Close() })
					payload := bytes.Repeat([]byte("t"), payloadSize)
					response := make([]byte, payloadSize)
					b.ReportAllocs()
					b.SetBytes(int64(payloadSize * 2))
					b.ResetTimer()
					for b.Loop() {
						if _, err := visitor.Write(payload); err != nil {
							b.Fatal(err)
						}
						if _, err := io.ReadFull(visitor, response); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func BenchmarkUDPProxyEndToEnd(b *testing.B) {
	disableBenchmarkLogging()
	for _, transportType := range []transport.Type{transport.TypeTCP, transport.TypeQUIC} {
		b.Run(string(transportType), func(b *testing.B) {
			echoConnection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				b.Fatal(err)
			}
			echoContext, cancelEcho := context.WithCancel(context.Background())
			go runUDPEchoServer(echoContext, echoConnection)
			b.Cleanup(func() {
				cancelEcho()
				echoConnection.Close()
			})

			proxyAddress := reserveUDPAddress(b)
			serverConfiguration, clientConfiguration := benchmarkTransportConfigurations(b, transportType)
			serverConfiguration.Proxies.BindIP = "127.0.0.1"
			clientConfiguration.Authentication.ClientID = "benchmark-udp-" + string(transportType)
			clientConfiguration.Proxies = []config.ProxyConfig{{
				Name: "echo", Type: "udp",
				Local: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(echoConnection.LocalAddr().(*net.UDPAddr).Port)},
				Public: config.ProxyPublicConfig{Port: uint16(proxyAddress.Port)},
			}}
			startBenchmarkServices(b, serverConfiguration, clientConfiguration)

			for _, payloadSize := range []int{64, 512, 1400, 8 * 1024} {
				b.Run(benchmarkPayloadName(payloadSize), func(b *testing.B) {
					visitor, err := net.DialUDP("udp", nil, proxyAddress)
					if err != nil {
						b.Fatal(err)
					}
					if err := visitor.SetDeadline(time.Now().Add(time.Hour)); err != nil {
						b.Fatal(err)
					}
					b.Cleanup(func() { visitor.Close() })
					payload := bytes.Repeat([]byte("u"), payloadSize)
					response := make([]byte, payloadSize)
					warmUDPProxy(b, visitor, payload, response)
					b.ReportAllocs()
					b.SetBytes(int64(payloadSize * 2))
					b.ResetTimer()
					for b.Loop() {
						if _, err := visitor.Write(payload); err != nil {
							b.Fatal(err)
						}
						length, err := visitor.Read(response)
						if err != nil {
							b.Fatal(err)
						}
						if length != len(payload) {
							b.Fatalf("unexpected UDP response length %d", length)
						}
					}
				})
			}
		})
	}
}

func BenchmarkHTTPProxyEndToEnd(b *testing.B) {
	disableBenchmarkLogging()
	for _, transportType := range []transport.Type{transport.TypeTCP, transport.TypeQUIC} {
		b.Run(string(transportType), func(b *testing.B) {
			backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				_, _ = io.Copy(writer, request.Body)
			}))
			b.Cleanup(backend.Close)
			backendAddress := backend.Listener.Addr().(*net.TCPAddr)
			httpAddress := reserveTCPAddress(b)
			serverConfiguration, clientConfiguration := benchmarkTransportConfigurations(b, transportType)
			serverConfiguration.Proxies.BindIP = "127.0.0.1"
			serverConfiguration.Proxies.HTTP.ListenAddress = httpAddress.String()
			clientConfiguration.Authentication.ClientID = "benchmark-http-" + string(transportType)
			clientConfiguration.Proxies = []config.ProxyConfig{{
				Name: "web", Type: "http",
				Local: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(backendAddress.Port)},
				Public: config.ProxyPublicConfig{Domain: "benchmark.example.com",
					Schemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP}},
			}}
			startBenchmarkServices(b, serverConfiguration, clientConfiguration)
			benchmarkHTTPPayloads(b, "http://"+httpAddress.String(), "benchmark.example.com", &http.Client{
				Transport: &http.Transport{MaxIdleConns: 256, MaxIdleConnsPerHost: 256},
			})
		})
	}
}

func BenchmarkHTTPSProxyEndToEnd(b *testing.B) {
	disableBenchmarkLogging()
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(writer, request.Body)
	}))
	b.Cleanup(backend.Close)
	backendAddress := backend.Listener.Addr().(*net.TCPAddr)
	httpsAddress := reserveTCPAddress(b)
	certificateFile, keyFile := writeServerCertificateForDNSNames(b, "benchmark.example.com")
	serverConfiguration, clientConfiguration := benchmarkTransportConfigurations(b, transport.TypeTCP)
	serverConfiguration.Proxies.BindIP = "127.0.0.1"
	serverConfiguration.Proxies.HTTPS.ListenAddress = httpsAddress.String()
	serverConfiguration.Proxies.HTTPS.Certificates = []config.HTTPSCertificateConfig{{
		Domains: []string{"benchmark.example.com"}, CertFile: certificateFile, KeyFile: keyFile,
	}}
	clientConfiguration.Authentication.ClientID = "benchmark-https"
	clientConfiguration.Proxies = []config.ProxyConfig{{
		Name: "web", Type: "http",
		Local: config.EndpointConfig{IP: "127.0.0.1", Port: uint16(backendAddress.Port)},
		Public: config.ProxyPublicConfig{Domain: "benchmark.example.com",
			Schemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTPS}},
	}}
	startBenchmarkServices(b, serverConfiguration, clientConfiguration)
	certificatePEM, err := os.ReadFile(certificateFile)
	if err != nil {
		b.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		b.Fatal("append benchmark certificate")
	}
	benchmarkHTTPPayloads(b, "https://"+httpsAddress.String(), "benchmark.example.com", &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, ServerName: "benchmark.example.com", RootCAs: roots,
		}, MaxIdleConns: 256, MaxIdleConnsPerHost: 256},
	})
}

func benchmarkTransportConfigurations(
	testingContext testing.TB,
	transportType transport.Type,
) (config.ServerConfig, config.ClientConfig) {
	serverConfiguration := config.DefaultServer()
	clientConfiguration := config.DefaultClient()
	if transportType == transport.TypeQUIC {
		certificateFile, keyFile := writeQUICServerCertificate(testingContext)
		address := reserveUDPAddress(testingContext).String()
		serverConfiguration.Transport.Type = transport.TypeQUIC
		serverConfiguration.Transport.ListenAddress = address
		serverConfiguration.Transport.QUIC.CertFile = certificateFile
		serverConfiguration.Transport.QUIC.KeyFile = keyFile
		clientConfiguration.Transport.Type = transport.TypeQUIC
		clientConfiguration.Transport.ServerAddress = address
		clientConfiguration.Transport.QUIC.ServerName = "localhost"
		clientConfiguration.Transport.QUIC.CAFile = certificateFile
	} else {
		address := reserveTCPAddress(testingContext).String()
		serverConfiguration.Transport.ListenAddress = address
		clientConfiguration.Transport.ServerAddress = address
	}
	serverConfiguration.Authentication.SharedToken = pointerTo(benchmarkToken)
	clientConfiguration.Authentication.Token = benchmarkToken
	return serverConfiguration, clientConfiguration
}

func startBenchmarkServices(
	b testing.TB,
	serverConfiguration config.ServerConfig,
	clientConfiguration config.ClientConfig,
) {
	serverContext, cancelServer := context.WithCancel(context.Background())
	clientContext, cancelClient := context.WithCancel(context.Background())
	services := benchmarkServices{
		cancelClient: cancelClient,
		cancelServer: cancelServer,
		clientErrors: make(chan error, 1),
		serverErrors: make(chan error, 1),
	}
	serverService := NewService(logging.New("benchmark-server"), serverConfiguration)
	clientService := client.NewService(logging.New("benchmark-client"), clientConfiguration)
	go func() { services.serverErrors <- serverService.Run(serverContext) }()
	go func() { services.clientErrors <- clientService.Run(clientContext) }()
	b.Cleanup(func() {
		services.cancelClient()
		if err := waitServiceResult(services.clientErrors); err != nil {
			b.Errorf("stop benchmark client: %v", err)
		}
		services.cancelServer()
		if err := waitServiceResult(services.serverErrors); err != nil {
			b.Errorf("stop benchmark server: %v", err)
		}
	})
}

func benchmarkHTTPPayloads(b *testing.B, address string, host string, httpClient *http.Client) {
	b.Cleanup(func() { httpClient.CloseIdleConnections() })
	for _, payloadSize := range []int{1024, 32 * 1024} {
		b.Run(benchmarkPayloadName(payloadSize), func(b *testing.B) {
			payload := bytes.Repeat([]byte("h"), payloadSize)
			doHTTPRequest := func() error {
				request, err := http.NewRequest(http.MethodPost, address+"/benchmark", bytes.NewReader(payload))
				if err != nil {
					return err
				}
				request.Host = host
				response, err := httpClient.Do(request)
				if err != nil {
					return err
				}
				_, copyError := io.Copy(io.Discard, response.Body)
				closeError := response.Body.Close()
				if copyError != nil {
					return copyError
				}
				if closeError != nil {
					return closeError
				}
				if response.StatusCode != http.StatusOK {
					return fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
				}
				return nil
			}
			warmHTTPProxy(b, doHTTPRequest)
			b.ReportAllocs()
			b.SetBytes(int64(payloadSize * 2))
			b.ResetTimer()
			for b.Loop() {
				if err := doHTTPRequest(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func warmUDPProxy(b testing.TB, connection *net.UDPConn, payload []byte, response []byte) {
	b.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_ = connection.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := connection.Write(payload); err == nil {
			if length, readError := connection.Read(response); readError == nil && length == len(payload) {
				_ = connection.SetReadDeadline(time.Now().Add(time.Hour))
				return
			}
		}
		if time.Now().After(deadline) {
			b.Fatal("UDP benchmark proxy did not become ready")
		}
	}
}

func warmHTTPProxy(b testing.TB, request func() error) {
	b.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := request(); err == nil {
			return
		} else if time.Now().After(deadline) {
			b.Fatalf("HTTP benchmark proxy did not become ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func benchmarkPayloadName(size int) string {
	switch size {
	case 64:
		return "64B"
	case 512:
		return "512B"
	case 1024:
		return "1KiB"
	case 1400:
		return "1400B"
	case 32 * 1024:
		return "32KiB"
	case 8 * 1024:
		return "8KiB"
	case 64 * 1024:
		return "64KiB"
	case 65507:
		return "65507B"
	case 1024 * 1024:
		return "1MiB"
	default:
		return "payload"
	}
}

func pointerTo[T any](value T) *T {
	return &value
}

func disableBenchmarkLogging() {
	toolkitlogger.Logrus().SetOutput(io.Discard)
}
