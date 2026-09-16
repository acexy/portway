//go:build !windows || !amd64

package vnet

func uninstallNetworkAuthorized() (string, error) {
	return UninstallNetwork()
}
