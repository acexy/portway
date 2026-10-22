//go:build !windows || !amd64

package system

func uninstallNetworkAuthorized() (string, error) {
	return UninstallNetwork()
}
