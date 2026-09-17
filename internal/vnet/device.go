package vnet

import (
	"context"
	"errors"
	"io"
)

// Device is one platform TUN endpoint carrying complete IPv4 packets.
type Device interface {
	io.Closer
	Name() string
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) (int, error)
}

type networkMigrator interface {
	MigrateNetwork(context.Context, NetworkSpec, NetworkSpec) error
}

// NetworkMigrationSupported reports whether a live device can adopt new network parameters.
func NetworkMigrationSupported(device Device) bool {
	_, supported := device.(networkMigrator)
	return supported
}

// MigrateNetworkContext updates a live device without replacing its packet endpoint.
func MigrateNetworkContext(ctx context.Context, device Device, previous, next NetworkSpec) error {
	migrator, supported := device.(networkMigrator)
	if !supported {
		return errors.New("live VNet network migration is unavailable on this platform")
	}
	if err := validateNetworkSpec(previous); err != nil {
		return err
	}
	if err := validateNetworkSpec(next); err != nil {
		return err
	}
	return migrator.MigrateNetwork(ctx, previous, next)
}

// OpenDevice opens the platform VNet device without changing addresses or routes.
func OpenDevice() (Device, error) {
	return openDevice()
}
