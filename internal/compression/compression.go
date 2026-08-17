// Package compression defines the data compression protocols supported by Portway.
package compression

// Algorithm identifies one data compression protocol.
type Algorithm string

const (
	// AlgorithmZstd identifies Zstandard stream compression.
	AlgorithmZstd Algorithm = "zstd"
)

// SupportedAlgorithms returns the compression protocols implemented by this binary.
func SupportedAlgorithms() []Algorithm {
	return []Algorithm{AlgorithmZstd}
}

// Supported reports whether this binary implements an algorithm.
func Supported(algorithm Algorithm) bool {
	return algorithm == AlgorithmZstd
}
