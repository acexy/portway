//go:build !linux && !darwin && (!windows || !amd64)

package vnet

import (
	"context"
	"errors"
)

func preparePlatformNetwork(context.Context, NetworkSpec) (Device, error) {
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
func networkUninstallSupported() bool           { return false }
func runtimeHelperSupported() bool             { return false }
func platformSupported() bool                  { return false }
func runtimeReprepareSupported() bool          { return false }
func runPlatformHelper([]string) (bool, error) { return false, nil }

func platformIdentityMatches(ownershipManifest) bool { return false }

func uninstallEphemeralNetwork() (string, bool, error) { return "", false, nil }
