package vnet

import "io"

// Device is one platform TUN endpoint carrying complete IPv4 packets.
type Device interface {
	io.Closer
	Name() string
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) (int, error)
}

// OpenDevice opens the platform VNet device without changing addresses or routes.
func OpenDevice() (Device, error) {
	return openDevice()
}
