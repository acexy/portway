//go:build darwin

package vnet

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	darwinUTUNControlName = "com.apple.net.utun_control"
	darwinUTUNOptionName  = 2
	darwinSystemControl   = 2
	darwinIPv4Family      = 2
)

type darwinDevice struct {
	fileDescriptor int
	name           string
	file           *os.File
	closeOnce      sync.Once
	closeError     error
}

func openDevice() (Device, error) {
	fileDescriptor, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, darwinSystemControl)
	if err != nil {
		return nil, fmt.Errorf("open macOS system control socket: %w", err)
	}
	controlInfo := &unix.CtlInfo{}
	for index, value := range []byte(darwinUTUNControlName) {
		controlInfo.Name[index] = value
	}
	if err := unix.IoctlCtlInfo(fileDescriptor, controlInfo); err != nil {
		unix.Close(fileDescriptor)
		return nil, fmt.Errorf("resolve macOS utun control: %w", err)
	}
	if err := unix.Connect(fileDescriptor, &unix.SockaddrCtl{ID: controlInfo.Id, Unit: 0}); err != nil {
		unix.Close(fileDescriptor)
		return nil, fmt.Errorf("connect macOS utun interface: %w", err)
	}
	name, err := unix.GetsockoptString(
		fileDescriptor,
		darwinSystemControl,
		darwinUTUNOptionName,
	)
	if err != nil {
		unix.Close(fileDescriptor)
		return nil, fmt.Errorf("read macOS utun interface name: %w", err)
	}
	return newDarwinDevice(fileDescriptor, strings.TrimRight(name, "\x00"))
}

func newDarwinDevice(fileDescriptor int, name string) (Device, error) {
	if err := unix.SetNonblock(fileDescriptor, true); err != nil {
		_ = unix.Close(fileDescriptor)
		return nil, err
	}
	file := os.NewFile(uintptr(fileDescriptor), name)
	if file == nil {
		_ = unix.Close(fileDescriptor)
		return nil, fmt.Errorf("invalid macOS VNet device descriptor")
	}
	// Pollable I/O lets Close interrupt a reader during address migration.
	if err := file.SetDeadline(time.Time{}); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("enable cancellable macOS VNet I/O: %w", err)
	}
	return &darwinDevice{fileDescriptor: fileDescriptor, name: name, file: file}, nil
}

func (device *darwinDevice) Name() string {
	return device.name
}

func (device *darwinDevice) ReadPacket(packet []byte) (int, error) {
	framed := make([]byte, len(packet)+4)
	for {
		read, err := device.file.Read(framed)
		if err != nil {
			return 0, err
		}
		// Unsupported address families are packet drops, not device failures.
		if read < 4 || binary.BigEndian.Uint32(framed[:4]) != darwinIPv4Family {
			continue
		}
		return copy(packet, framed[4:read]), nil
	}
}

func (device *darwinDevice) WritePacket(packet []byte) (int, error) {
	framed := make([]byte, len(packet)+4)
	binary.BigEndian.PutUint32(framed[:4], darwinIPv4Family)
	copy(framed[4:], packet)
	written, err := device.file.Write(framed)
	if err != nil {
		return 0, err
	}
	if written != len(framed) {
		return 0, io.ErrShortWrite
	}
	return len(packet), nil
}

func (device *darwinDevice) Close() error {
	device.closeOnce.Do(func() { device.closeError = device.file.Close() })
	return device.closeError
}
