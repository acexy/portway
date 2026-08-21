//go:build darwin

package config

import "golang.org/x/sys/unix"

func platformUDPMaxDatagramSize() (int, error) {
	maximum, err := unix.SysctlUint32("net.inet.udp.maxdgram")
	if err != nil {
		return 0, err
	}
	return min(int(maximum), udpHardMaxDatagramSize), nil
}
