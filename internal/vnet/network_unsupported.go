//go:build !linux && !darwin

package vnet

import "errors"

func preparePlatformNetwork(NetworkSpec) (Device, error) {
	return nil, errors.New("VNet is supported only on Linux and macOS")
}
func uninstallPlatformNetwork(ownershipManifest) error {
	return errors.New("VNet is supported only on Linux and macOS")
}
func repairPlatformNetwork(NetworkSpec) (Device, error) {
	return nil, errors.New("VNet is supported only on Linux and macOS")
}
func platformRootGroup() string                { return "root" }
func manualNetworkManagementSupported() bool   { return false }
func runtimeHelperSupported() bool             { return false }
func runPlatformHelper([]string) (bool, error) { return false, nil }
