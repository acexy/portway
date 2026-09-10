package ipfilter

import (
	"errors"
	"net"
	"sync"
)

type trackedConnection struct {
	net.Conn
	release   func()
	closeOnce sync.Once
}

// WrapListener rejects denied socket peers before returning accepted
// connections and tracks allowed connections for dynamic rule enforcement.
func WrapListener(listener net.Listener, filter *Filter) net.Listener {
	return WrapListenerFor(listener, filter, "socket")
}

// WrapListenerFor filters socket peers and classifies deny events by ingress.
func WrapListenerFor(listener net.Listener, filter *Filter, ingress string) net.Listener {
	if !filter.Enabled() {
		return listener
	}
	return &filteredListener{Listener: listener, filter: filter, ingress: ingress}
}

type filteredListener struct {
	net.Listener
	filter  *Filter
	ingress string
}

func (listener *filteredListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		address, err := ParseRemoteAddress(connection.RemoteAddr())
		if err != nil {
			connection.Close()
			continue
		}
		tracked := &trackedConnection{Conn: connection}
		release, allowed := listener.filter.RegisterFor(address, listener.ingress, func() {
			connection.Close()
		})
		if !allowed {
			connection.Close()
			continue
		}
		tracked.release = release
		return tracked, nil
	}
}

func (connection *trackedConnection) Close() error {
	var closeError error
	connection.closeOnce.Do(func() {
		closeError = connection.Conn.Close()
		if connection.release != nil {
			connection.release()
		}
	})
	return closeError
}

// CloseWrite preserves TCP half-close through source tracking wrappers.
func (connection *trackedConnection) CloseWrite() error {
	closeWriter, ok := connection.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.New("tracked connection does not support write half-close")
	}
	return closeWriter.CloseWrite()
}

// CloseRead preserves read half-close through source tracking wrappers.
func (connection *trackedConnection) CloseRead() error {
	closeReader, ok := connection.Conn.(interface{ CloseRead() error })
	if !ok {
		return errors.New("tracked connection does not support read half-close")
	}
	return closeReader.CloseRead()
}
