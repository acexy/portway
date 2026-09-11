//go:build !linux && !darwin

package vnet

import "errors"

func openDevice() (Device, error) {
	return nil, errors.New("VNet is supported only on Linux and macOS")
}
