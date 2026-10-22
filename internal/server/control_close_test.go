package server

import (
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestControlCloseDeliveryWaitIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, remote := net.Pipe()
		defer local.Close()
		defer remote.Close()
		stream := &closeTrackingStream{Conn: local}
		started := time.Now()
		if err := finishControlSession(stream); err != nil {
			t.Fatal(err)
		}
		if time.Since(started) != controlCloseDeliveryTimeout {
			t.Fatalf("delivery wait duration = %v", time.Since(started))
		}
		if stream.closeCalls != 0 || stream.closeWriteCalls != 1 {
			t.Fatalf("delivery wait closed the whole connection: %+v", stream)
		}
	})
}

func TestControlCloseDeliveryWaitEndsOnPeerClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, remote := net.Pipe()
		defer local.Close()
		defer remote.Close()
		stream := &closeTrackingStream{Conn: local}
		done := make(chan error, 1)
		started := time.Now()
		go func() { done <- finishControlSession(stream) }()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("returned before peer closed: %v", err)
		default:
		}
		if _, err := remote.Write([]byte("discarded after close")); err != nil {
			t.Fatal(err)
		}
		remote.Close()
		if err := <-done; err != nil || time.Since(started) != 0 {
			t.Fatalf("peer close did not promptly end wait: %v", err)
		}
	})
}

func TestControlCloseDeliveryWaitEndsOnLocalClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, remote := net.Pipe()
		defer remote.Close()
		defer local.Close()
		done := make(chan error, 1)
		go func() { done <- finishControlSession(&closeTrackingStream{Conn: local}) }()
		synctest.Wait()
		local.Close()
		if err := <-done; err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	})
}
