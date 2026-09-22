//go:build !linux && !darwin && (!windows || !amd64)

package vnet

import "errors"

func openDevice() (Device, error) {
	return nil, errors.New("VNet is unsupported on this platform")
}
