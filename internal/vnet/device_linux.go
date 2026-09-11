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
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open Linux TUN device: %w", err)
	}
	request, err := unix.NewIfreq(linuxVNetInterfaceName)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("prepare Linux TUN interface: %w", err)
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(int(file.Fd()), unix.TUNSETIFF, request); err != nil {
		file.Close()
		return nil, fmt.Errorf("open Linux TUN interface %q: %w", linuxVNetInterfaceName, err)
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
