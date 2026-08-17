package client

import (
	"errors"
	"testing"

	"github.com/acexy/portway/internal/compression"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

func TestValidateCompressionRequirement(t *testing.T) {
	tests := []struct {
		name        string
		requirement protocol.CompressionRequirement
		wantError   bool
	}{
		{name: "disabled"},
		{
			name: "zstd",
			requirement: protocol.CompressionRequirement{
				Enabled: true, Algorithm: compression.AlgorithmZstd,
			},
		},
		{
			name: "disabled with algorithm",
			requirement: protocol.CompressionRequirement{
				Algorithm: compression.AlgorithmZstd,
			},
			wantError: true,
		},
		{
			name: "unsupported",
			requirement: protocol.CompressionRequirement{
				Enabled: true, Algorithm: compression.Algorithm("unknown"),
			},
			wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateCompressionRequirement(test.requirement)
			if (err != nil) != test.wantError {
				t.Fatalf("validateCompressionRequirement() error = %v", err)
			}
			if test.wantError && !errors.Is(err, transport.ErrProtocol) {
				t.Fatalf("error = %v, want protocol error", err)
			}
		})
	}
}
