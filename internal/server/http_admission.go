package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

const maxPublicHTTPConnections = 4096
const publicTLSHandshakeTimeout = 10 * time.Second

// publicHTTPAdmission owns both public listeners' connection slots, including
// idle, pre-header and hijacked connections. Closing the socket releases its slot.
type publicHTTPAdmission struct {
	mutex       sync.Mutex
	connections map[*publicHTTPConnection]struct{}
	limit       int
	closed      bool
	handshakes  sync.WaitGroup
}

type publicHTTPListener struct {
	net.Listener
	admission *publicHTTPAdmission
	tlsConfig *tls.Config
}

type publicHTTPConnection struct {
	net.Conn
	once      sync.Once
	admission *publicHTTPAdmission
	timer     *time.Timer
}

func (admission *publicHTTPAdmission) wrap(listener net.Listener, configuration *tls.Config) net.Listener {
	return &publicHTTPListener{Listener: listener, admission: admission, tlsConfig: configuration}
}

func (listener *publicHTTPListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		admission := listener.admission
		admission.mutex.Lock()
		if admission.closed {
			admission.mutex.Unlock()
			_ = connection.Close()
			return nil, net.ErrClosed
		}
		if len(admission.connections) >= admission.limit {
			admission.mutex.Unlock()
			_ = connection.Close()
			continue
		}
		tracked := &publicHTTPConnection{Conn: connection, admission: admission}
		admission.connections[tracked] = struct{}{}
		var accepted net.Conn = tracked
		if listener.tlsConfig != nil {
			secure := tls.Server(tracked, listener.tlsConfig)
			// This independent timer also applies when header deadlines are disabled.
			tracked.timer = time.AfterFunc(publicTLSHandshakeTimeout, func() {
				_ = tracked.Close()
			})
			admission.handshakes.Go(func() {
				err := secure.Handshake()
				admission.mutex.Lock()
				tracked.timer.Stop()
				admission.mutex.Unlock()
				if err != nil {
					_ = tracked.Close()
				}
			})
			accepted = secure
		}
		admission.mutex.Unlock()
		return accepted, nil
	}
}

func (connection *publicHTTPConnection) Close() error {
	var err error
	connection.once.Do(func() {
		err = connection.Conn.Close()
		connection.admission.mutex.Lock()
		if connection.timer != nil {
			connection.timer.Stop()
		}
		delete(connection.admission.connections, connection)
		connection.admission.mutex.Unlock()
	})
	return err
}

// CloseWrite preserves half-close for hijacked public HTTP connections.
func (connection *publicHTTPConnection) CloseWrite() error {
	closeWriter, ok := connection.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.New("public HTTP connection does not support write half-close")
	}
	return closeWriter.CloseWrite()
}

// CloseRead preserves read half-close for hijacked public HTTP connections.
func (connection *publicHTTPConnection) CloseRead() error {
	closeReader, ok := connection.Conn.(interface{ CloseRead() error })
	if !ok {
		return errors.New("public HTTP connection does not support read half-close")
	}
	return closeReader.CloseRead()
}

func (admission *publicHTTPAdmission) close() {
	admission.mutex.Lock()
	admission.closed = true
	connections := make([]*publicHTTPConnection, 0, len(admission.connections))
	for connection := range admission.connections {
		connections = append(connections, connection)
	}
	admission.mutex.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	admission.handshakes.Wait()
}

// Keep public connections attached to the server lifecycle, including TLS handshakes.
func publicHTTPBaseContext(ctx context.Context) func(net.Listener) context.Context {
	return func(net.Listener) context.Context { return ctx }
}
