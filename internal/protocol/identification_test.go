package protocol

import (
	"strings"
	"testing"
)

func TestValidateClientIdentification(t *testing.T) {
	valid := ClientIdentification{
		Product:  ProductClient,
		Version:  "v0.0.1",
		OS:       OperatingSystemDarwin,
		Arch:     ArchitectureARM64,
		Hostname: "jaide-mac",
	}
	if err := ValidateClientIdentification(valid); err != nil {
		t.Fatalf("ValidateClientIdentification() error = %v", err)
	}

	tests := []struct {
		name           string
		identification ClientIdentification
	}{
		{
			name: "wrong product",
			identification: func() ClientIdentification {
				value := valid
				value.Product = ProductServer
				return value
			}(),
		},
		{
			name: "empty version",
			identification: func() ClientIdentification {
				value := valid
				value.Version = ""
				return value
			}(),
		},
		{
			name: "unsupported operating system",
			identification: func() ClientIdentification {
				value := valid
				value.OS = "plan9"
				return value
			}(),
		},
		{
			name: "unsupported architecture",
			identification: func() ClientIdentification {
				value := valid
				value.Arch = "386"
				return value
			}(),
		},
		{
			name: "unsupported platform",
			identification: func() ClientIdentification {
				value := valid
				value.OS = OperatingSystemWindows
				return value
			}(),
		},
		{
			name: "hostname control character",
			identification: func() ClientIdentification {
				value := valid
				value.Hostname = "host\nname"
				return value
			}(),
		},
		{
			name: "hostname too long",
			identification: func() ClientIdentification {
				value := valid
				value.Hostname = strings.Repeat("a", maxHostnameLength+1)
				return value
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateClientIdentification(test.identification); err == nil {
				t.Fatal("ValidateClientIdentification() error = nil")
			}
		})
	}
}

func TestValidateServerIdentification(t *testing.T) {
	if err := ValidateServerIdentification(ServerIdentification{
		Product: ProductServer,
		Version: "development",
	}); err != nil {
		t.Fatalf("ValidateServerIdentification() error = %v", err)
	}
	if err := ValidateServerIdentification(ServerIdentification{
		Product: ProductClient,
		Version: "v0.0.1",
	}); err == nil {
		t.Fatal("ValidateServerIdentification() error = nil")
	}
}
