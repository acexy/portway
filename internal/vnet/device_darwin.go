//go:build darwin

package vnet

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

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
	return &darwinDevice{fileDescriptor: fileDescriptor, name: strings.TrimRight(name, "\x00")}, nil
}

func (device *darwinDevice) Name() string {
	return device.name
}

func (device *darwinDevice) ReadPacket(packet []byte) (int, error) {
	framed := make([]byte, len(packet)+4)
	read, err := unix.Read(device.fileDescriptor, framed)
	if err != nil {
		return 0, err
	}
	if read < 4 || binary.BigEndian.Uint32(framed[:4]) != darwinIPv4Family {
		return 0, fmt.Errorf("%w: invalid macOS utun address family", ErrInvalidPacket)
	}
	return copy(packet, framed[4:read]), nil
}

func (device *darwinDevice) WritePacket(packet []byte) (int, error) {
	framed := make([]byte, len(packet)+4)
	binary.BigEndian.PutUint32(framed[:4], darwinIPv4Family)
	copy(framed[4:], packet)
	written, err := unix.Write(device.fileDescriptor, framed)
	if err != nil {
		return 0, err
	}
	if written != len(framed) {
		return 0, io.ErrShortWrite
	}
	return len(packet), nil
}

func (device *darwinDevice) Close() error {
	return unix.Close(device.fileDescriptor)
}
