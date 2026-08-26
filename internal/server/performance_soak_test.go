package server

import (
	"bytes"
	"context"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

var performanceSoakDuration = flag.Duration(
	"portway-soak-duration",
	0,
	"duration of the opt-in mixed proxy performance soak test",
)

var performanceSoakTransport = flag.String(
	"portway-soak-transport",
	string(transport.TypeTCP),
	"transport used by the opt-in performance soak test: tcp or quic",
)

func TestPerformanceSoak(t *testing.T) {
	if *performanceSoakDuration <= 0 {
		t.Skip("set -portway-soak-duration to enable the performance soak test")
	}
	transportType := transport.Type(*performanceSoakTransport)
	if transportType != transport.TypeTCP && transportType != transport.TypeQUIC {
		t.Fatalf("unsupported soak transport %q", transportType)
	}
	disableBenchmarkLogging()

	tcpBackend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpBackendContext, cancelTCPBackend := context.WithCancel(context.Background())
	go runEchoServer(tcpBackendContext, tcpBackend)
	t.Cleanup(func() {
		cancelTCPBackend()
		tcpBackend.Close()
	})
	udpBackend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	udpBackendContext, cancelUDPBackend := context.WithCancel(context.Background())
	go runUDPEchoServer(udpBackendContext, udpBackend)
	t.Cleanup(func() {
		cancelUDPBackend()
		udpBackend.Close()
	})
	httpBackend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(writer, request.Body)
	}))
	t.Cleanup(httpBackend.Close)

	tcpProxyAddress := reserveTCPAddress(t)
	udpProxyAddress := reserveUDPAddress(t)
	httpProxyAddress := reserveTCPAddress(t)
	serverConfiguration, clientConfiguration := benchmarkTransportConfigurations(t, transportType)
	serverConfiguration.Tunnel.BindIP = "127.0.0.1"
	serverConfiguration.Tunnel.HTTPListenAddress = httpProxyAddress.String()
	clientConfiguration.ClientID = "soak-" + string(transportType)
	clientConfiguration.Proxies = []config.ProxyConfig{
		{
			Name: "tcp", Type: "tcp", LocalIP: "127.0.0.1",
			LocalPort:  uint16(tcpBackend.Addr().(*net.TCPAddr).Port),
			RemotePort: uint16(tcpProxyAddress.Port),
		},
		{
			Name: "udp", Type: "udp", LocalIP: "127.0.0.1",
			LocalPort:  uint16(udpBackend.LocalAddr().(*net.UDPAddr).Port),
			RemotePort: uint16(udpProxyAddress.Port),
		},
		{
			Name: "http", Type: "http", Domain: "soak.example.com",
			LocalIP:       "127.0.0.1",
			LocalPort:     uint16(httpBackend.Listener.Addr().(*net.TCPAddr).Port),
			PublicSchemes: []protocol.HTTPPublicScheme{protocol.HTTPPublicSchemeHTTP},
		},
	}
	startBenchmarkServices(t, serverConfiguration, clientConfiguration)

	tcpVisitor := dialWithRetry(t, tcpProxyAddress.String(), 10*time.Second)
	t.Cleanup(func() { tcpVisitor.Close() })
	udpVisitor, err := net.DialUDP("udp", nil, udpProxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udpVisitor.Close() })
	udpPayload := bytes.Repeat([]byte("u"), 1400)
	warmUDPProxy(t, udpVisitor, udpPayload, make([]byte, len(udpPayload)))
	httpClient := &http.Client{Transport: &http.Transport{
		MaxIdleConns: 64, MaxIdleConnsPerHost: 64,
	}}
	t.Cleanup(httpClient.CloseIdleConnections)
	doHTTPRequest := func() error {
		request, requestError := http.NewRequest(
			http.MethodPost,
			"http://"+httpProxyAddress.String()+"/soak",
			bytes.NewReader(bytes.Repeat([]byte("h"), 1024)),
		)
		if requestError != nil {
			return requestError
		}
		request.Host = "soak.example.com"
		response, requestError := httpClient.Do(request)
		if requestError != nil {
			return requestError
		}
		_, copyError := io.Copy(io.Discard, response.Body)
		closeError := response.Body.Close()
		if copyError != nil {
			return copyError
		}
		return closeError
	}
	warmHTTPProxy(t, doHTTPRequest)

	var startMemory runtime.MemStats
	runtime.ReadMemStats(&startMemory)
	startGoroutines := runtime.NumGoroutine()
	loadContext, cancelLoad := context.WithTimeout(context.Background(), *performanceSoakDuration)
	defer cancelLoad()
	var tcpOperations atomic.Uint64
	var udpOperations atomic.Uint64
	var httpOperations atomic.Uint64
	errorsChannel := make(chan error, 3)
	var waitGroup sync.WaitGroup
	waitGroup.Go(func() {
		runTCPSoakLoad(loadContext, tcpVisitor, &tcpOperations, errorsChannel)
	})
	waitGroup.Go(func() {
		runUDPSoakLoad(loadContext, udpVisitor, udpPayload, &udpOperations, errorsChannel)
	})
	waitGroup.Go(func() {
		runHTTPSoakLoad(loadContext, doHTTPRequest, &httpOperations, errorsChannel)
	})
	waitGroup.Wait()
	close(errorsChannel)
	for loadError := range errorsChannel {
		if loadError != nil {
			t.Fatal(loadError)
		}
	}

	var endMemory runtime.MemStats
	runtime.ReadMemStats(&endMemory)
	t.Logf(
		"transport=%s duration=%s tcp_ops=%d udp_ops=%d http_ops=%d heap_start=%d heap_end=%d heap_objects_start=%d heap_objects_end=%d gc_delta=%d goroutines_start=%d goroutines_end=%d",
		transportType,
		*performanceSoakDuration,
		tcpOperations.Load(),
		udpOperations.Load(),
		httpOperations.Load(),
		startMemory.HeapAlloc,
		endMemory.HeapAlloc,
		startMemory.HeapObjects,
		endMemory.HeapObjects,
		endMemory.NumGC-startMemory.NumGC,
		startGoroutines,
		runtime.NumGoroutine(),
	)
}

func runTCPSoakLoad(
	ctx context.Context,
	connection net.Conn,
	operations *atomic.Uint64,
	errorsChannel chan<- error,
) {
	payload := bytes.Repeat([]byte("t"), 32*1024)
	response := make([]byte, len(payload))
	for ctx.Err() == nil {
		if _, err := connection.Write(payload); err != nil {
			if ctx.Err() == nil {
				errorsChannel <- err
			}
			return
		}
		if _, err := io.ReadFull(connection, response); err != nil {
			if ctx.Err() == nil {
				errorsChannel <- err
			}
			return
		}
		operations.Add(1)
	}
}

func runUDPSoakLoad(
	ctx context.Context,
	connection *net.UDPConn,
	payload []byte,
	operations *atomic.Uint64,
	errorsChannel chan<- error,
) {
	response := make([]byte, len(payload))
	for ctx.Err() == nil {
		if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
			errorsChannel <- err
			return
		}
		if _, err := connection.Write(payload); err != nil {
			if ctx.Err() == nil {
				errorsChannel <- err
			}
			return
		}
		if _, err := connection.Read(response); err != nil {
			if ctx.Err() == nil {
				errorsChannel <- err
			}
			return
		}
		operations.Add(1)
	}
}

func runHTTPSoakLoad(
	ctx context.Context,
	request func() error,
	operations *atomic.Uint64,
	errorsChannel chan<- error,
) {
	for ctx.Err() == nil {
		if err := request(); err != nil {
			if ctx.Err() == nil {
				errorsChannel <- err
			}
			return
		}
		operations.Add(1)
	}
}
