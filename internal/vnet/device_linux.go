//go:build linux

package vnet

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const linuxVNetInterfaceName = "portway0"

type linuxDevice struct {
	file *os.File
}

func openDevice() (Device, error) {
	// Attach the TUN interface before os.NewFile registers the descriptor with
	// the Go runtime poller. An unattached /dev/net/tun descriptor is not
	// pollable on some Linux kernels and remains unusable after TUNSETIFF.
	descriptor, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open Linux TUN device: %w", err)
	}
	request, err := unix.NewIfreq(linuxVNetInterfaceName)
	if err != nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("prepare Linux TUN interface: %w", err)
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(descriptor, unix.TUNSETIFF, request); err != nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("open Linux TUN interface %q: %w", linuxVNetInterfaceName, err)
	}
	file := os.NewFile(uintptr(descriptor), "/dev/net/tun")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("manage Linux TUN interface %q", linuxVNetInterfaceName)
	}
	return &linuxDevice{file: file}, nil
}

func (device *linuxDevice) Name() string {
	return linuxVNetInterfaceName
}

func (device *linuxDevice) ReadPacket(packet []byte) (int, error) {
	return device.file.Read(packet)
}

func (device *linuxDevice) WritePacket(packet []byte) (int, error) {
	return device.file.Write(packet)
}

func (device *linuxDevice) Close() error {
	return device.file.Close()
}
