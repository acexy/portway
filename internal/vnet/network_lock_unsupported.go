//go:build !linux && !darwin

package vnet

import (
	"errors"
	"os"
)

func lockNetworkFile(*os.File, bool) error { return errors.New("VNet file locking is unsupported") }
func unlockNetworkFile(*os.File) error     { return nil }
func safeManifestFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0022 == 0
}
