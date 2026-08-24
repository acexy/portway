//go:build !darwin

package config

func platformUDPMaxDatagramSize() (int, error) {
	return udpHardMaxDatagramSize, nil
}
