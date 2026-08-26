package http

import (
	"errors"
	"net"
	"sync"
	"time"
)

// idleTimeoutConnection closes an upgraded connection after a full-duplex idle period.
type idleTimeoutConnection struct {
	net.Conn
	timeout time.Duration
	timer   *time.Timer
	mutex   sync.Mutex
	closed  bool
}

func newIdleTimeoutConnection(connection net.Conn, timeout time.Duration) net.Conn {
	if timeout <= 0 {
		return connection
	}
	wrapper := &idleTimeoutConnection{Conn: connection, timeout: timeout}
	initialized := make(chan struct{})
	wrapper.timer = time.AfterFunc(timeout, func() {
		<-initialized
		_ = wrapper.Close()
	})
	close(initialized)
	return wrapper
}

func (connection *idleTimeoutConnection) Read(buffer []byte) (int, error) {
	read, err := connection.Conn.Read(buffer)
	if read > 0 {
		connection.touch()
	}
	return read, err
}

func (connection *idleTimeoutConnection) Write(buffer []byte) (int, error) {
	written, err := connection.Conn.Write(buffer)
	if written > 0 {
		connection.touch()
	}
	return written, err
}

func (connection *idleTimeoutConnection) touch() {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	if !connection.closed {
		connection.timer.Reset(connection.timeout)
	}
}

func (connection *idleTimeoutConnection) Close() error {
	connection.mutex.Lock()
	if connection.closed {
		connection.mutex.Unlock()
		return nil
	}
	connection.closed = true
	connection.timer.Stop()
	connection.mutex.Unlock()
	return connection.Conn.Close()
}

func (connection *idleTimeoutConnection) CloseWrite() error {
	closeWriter, ok := connection.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.New("connection does not support half-close")
	}
	return closeWriter.CloseWrite()
}

func (connection *idleTimeoutConnection) CloseRead() error {
	closeReader, ok := connection.Conn.(interface{ CloseRead() error })
	if !ok {
		return errors.New("connection does not support read half-close")
	}
	return closeReader.CloseRead()
}
