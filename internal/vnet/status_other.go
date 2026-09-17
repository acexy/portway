//go:build !windows || !amd64

package vnet

func networkStatusSupported() bool { return false }

func inspectEphemeralNetwork() (NetworkStatus, bool, error) {
	return NetworkStatus{}, false, nil
}
