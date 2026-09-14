package server

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/acexy/portway/internal/config"
)

type queuedHTTPListener struct {
	connections chan net.Conn
	done        chan struct{}
}

type halfCloseConnection struct {
	net.Conn
	writeClosed atomic.Bool
	readClosed  atomic.Bool
}

func (connection *halfCloseConnection) CloseWrite() error {
	connection.writeClosed.Store(true)
	return nil
}

func (connection *halfCloseConnection) CloseRead() error {
	connection.readClosed.Store(true)
	return nil
}

func (l *queuedHTTPListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connections:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *queuedHTTPListener) Close() error   { close(l.done); return nil }
func (l *queuedHTTPListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestPublicHTTPConnectionPreservesHalfClose(t *testing.T) {
	underlying, peer := net.Pipe()
	defer peer.Close()
	capable := &halfCloseConnection{Conn: underlying}
	admission := &publicHTTPAdmission{connections: make(map[*publicHTTPConnection]struct{})}
	connection := &publicHTTPConnection{Conn: capable, admission: admission}
	admission.connections[connection] = struct{}{}
	defer connection.Close()

	if err := connection.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
	if err := connection.CloseRead(); err != nil {
		t.Fatalf("CloseRead() error = %v", err)
	}
	if !capable.writeClosed.Load() || !capable.readClosed.Load() {
		t.Fatal("public HTTP connection did not preserve half-close operations")
	}
}

func TestPublicHTTPAdmissionSharesSlotsAndExpiresTLSHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		admission := &publicHTTPAdmission{limit: 1, connections: make(map[*publicHTTPConnection]struct{})}
		defer admission.close()
		plain := &queuedHTTPListener{make(chan net.Conn, 2), make(chan struct{})}
		secure := &queuedHTTPListener{make(chan net.Conn, 1), make(chan struct{})}
		defer plain.Close()
		defer secure.Close()
		server, stalled := net.Pipe()
		defer stalled.Close()
		secure.connections <- server
		accepted, err := admission.wrap(secure, &tls.Config{MinVersion: tls.VersionTLS12}).Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer accepted.Close()
		rejectedServer, rejected := net.Pipe()
		defer rejected.Close()
		plain.connections <- rejectedServer
		admitted := make(chan net.Conn, 1)
		go func() { c, _ := admission.wrap(plain, nil).Accept(); admitted <- c }()
		if _, err := rejected.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("over-limit connection not rejected: %v", err)
		}
		time.Sleep(publicTLSHandshakeTimeout + time.Second)
		if _, err := stalled.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("TLS handshake did not expire: %v", err)
		}
		nextServer, next := net.Pipe()
		defer next.Close()
		plain.connections <- nextServer
		connection := <-admitted
		if connection == nil {
			t.Fatal("released TLS slot was not reusable")
		}
		connection.Close()
		connection.Close()
		admission.mutex.Lock()
		defer admission.mutex.Unlock()
		if len(admission.connections) != 0 {
			t.Fatal("connection slots leaked")
		}
	})
}

func TestPublicHTTPHeaderDeadlineReleasesAdmissionSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		admission := &publicHTTPAdmission{limit: 1, connections: make(map[*publicHTTPConnection]struct{})}
		defer admission.close()
		listener := &queuedHTTPListener{make(chan net.Conn, 1), make(chan struct{})}
		configuration := config.DefaultServer().Proxies.HTTP.HTTPConfig
		var handled atomic.Bool
		server := &http.Server{ReadHeaderTimeout: configuration.ReadHeaderTimeout, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { handled.Store(true) })}
		done := make(chan error, 1)
		go func() { done <- server.Serve(admission.wrap(listener, nil)) }()
		serverSide, visitor := net.Pipe()
		defer visitor.Close()
		listener.connections <- serverSide
		if _, err := visitor.Write([]byte("GET / HTTP/1.1\r\nHost: incomplete")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(configuration.ReadHeaderTimeout + time.Second)
		synctest.Wait()
		admission.mutex.Lock()
		remaining := len(admission.connections)
		admission.mutex.Unlock()
		if remaining != 0 || handled.Load() {
			t.Fatalf("incomplete request survived: slots=%d handled=%v", remaining, handled.Load())
		}
		server.Close()
		if err := <-done; err != http.ErrServerClosed {
			t.Fatal(err)
		}
	})
}
