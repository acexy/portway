package http

import (
	"net"
	"testing"
	"time"
)

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
	connection := newIdleTimeoutConnection(server, 40*time.Millisecond)
	defer connection.Close()
	defer client.Close()

	for index := 0; index < 3; index++ {
		// perform the write synchronously so the data is available for Read()
		if _, err := client.Write([]byte{1}); err != nil {
			t.Fatalf("write activity %d: %v", index, err)
		}
		if _, err := connection.Read(make([]byte, 1)); err != nil {
			t.Fatalf("read activity %d: %v", index, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection remained open after refreshed timeout elapsed")
	}
}
