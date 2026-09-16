//go:build !windows || !amd64

package vnet

// ElevateCurrentProcess is a no-op on platforms without Windows UAC.
func ElevateCurrentProcess() (exitCode int, relaunched bool, err error) {
	return 0, false, nil
}
