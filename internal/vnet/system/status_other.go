//go:build !windows || !amd64

package system

func networkStatusSupported() bool { return false }

func inspectEphemeralNetwork() (NetworkStatus, bool, error) {
	return NetworkStatus{}, false, nil
}
