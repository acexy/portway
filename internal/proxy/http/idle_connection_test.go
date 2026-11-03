package http

import (
	"net"
	"testing"
	"time"
)

func TestIdleTimeoutCallbackRechecksActivityAndClosedState(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	connection := newIdleTimeoutConnection(server, time.Hour).(*idleTimeoutConnection)
	defer connection.Close()
	// Simulate an old timer callback dispatched before a successful I/O refresh.
	connection.mutex.Lock()
	connection.deadline = time.Now().Add(-time.Second)
	connection.mutex.Unlock()
	connection.touch()
	connection.expire()
	connection.mutex.Lock()
	closed := connection.closed
	connection.mutex.Unlock()
	if closed {
		t.Fatal("stale timer callback closed an active connection")
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	connection.mutex.Lock()
	connection.deadline = time.Now().Add(-time.Second)
	connection.mutex.Unlock()
	connection.expire()
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("expired connection remained open")
	}
	connection.touch()
	connection.expire()
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	if !connection.closed {
		t.Fatal("late activity revived a closed connection")
	}
}

func TestIdleTimeoutConnectionClosesAfterInactivity(t *testing.T) {
	server, client := net.Pipe()
	connection := newIdleTimeoutConnection(server, 20*time.Millisecond)
	defer connection.Close()
	defer client.Close()

	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle connection remained open")
	}
}

func TestIdleTimeoutConnectionRefreshesOnActivity(t *testing.T) {
	server, client := net.Pipe()
	connection := newIdleTimeoutConnection(server, 500*time.Millisecond)
	defer connection.Close()
	defer client.Close()

	for index := 0; index < 3; index++ {
		writeErrors := make(chan error, 1)
		go func() {
			_, err := client.Write([]byte{1})
			writeErrors <- err
		}()
		if _, err := connection.Read(make([]byte, 1)); err != nil {
			t.Fatalf("read activity %d: %v", index, err)
		}
		if err := <-writeErrors; err != nil {
			t.Fatalf("write activity %d: %v", index, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection remained open after refreshed timeout elapsed")
	}
}
