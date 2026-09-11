//go:build linux || darwin

package vnet

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func safeManifestFile(info os.FileInfo) bool {
	stat, valid := info.Sys().(*syscall.Stat_t)
	return valid && info.Mode().IsRegular() && info.Mode().Perm()&0022 == 0 && stat.Uid == 0
}

func lockNetworkFile(file *os.File, exclusive bool) error {
	operation := unix.LOCK_SH | unix.LOCK_NB
	if exclusive {
		operation = unix.LOCK_EX | unix.LOCK_NB
	}
	return unix.Flock(int(file.Fd()), operation)
}

func unlockNetworkFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
