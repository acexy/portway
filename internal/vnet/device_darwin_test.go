//go:build darwin

package vnet

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDarwinDeviceSkipsUnsupportedAddressFamilies(t *testing.T) {
	descriptors, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(descriptors[1])
	device, err := newDarwinDevice(descriptors[0], "test-utun")
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	for _, packet := range [][]byte{{0}, {0, 0, 0, 30, 0x60}, {0, 0, 0, 2, 0x45}} {
		if _, err := unix.Write(descriptors[1], packet); err != nil {
			t.Fatal(err)
		}
	}
	buffer := make([]byte, 1150)
	count, err := device.ReadPacket(buffer)
	if err != nil || count != 1 || buffer[0] != 0x45 {
		t.Fatalf("non-IPv4 packet stopped the device: count=%d err=%v", count, err)
	}
}

func TestDarwinDeviceCloseCancelsReadAndIsIdempotent(t *testing.T) {
	descriptors, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(descriptors[1])
	device, err := newDarwinDevice(descriptors[0], "test-utun")
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	packet := []byte{0, 0, 0, 2, 1}
	if _, err := unix.Write(descriptors[1], packet); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1280)
		if _, err := device.ReadPacket(buffer); err != nil {
			finished <- err
			close(ready)
			return
		}
		close(ready)
		_, err := device.ReadPacket(buffer)
		finished <- err
	}()
	<-ready
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("repeated close is not idempotent: %v", err)
	}
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("closed device continued reading")
		}
	case <-time.After(time.Second):
		t.Fatal("device close did not interrupt its reader")
	}
}
