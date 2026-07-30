package protocol

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxProductLength  = 32
	maxVersionLength  = 64
	maxHostnameLength = 255
)

// Product identifies a Portway executable in the control protocol.
type Product string

const (
	// ProductClient identifies the Portway client executable.
	ProductClient Product = "portway-client"
	// ProductServer identifies the Portway server executable.
	ProductServer Product = "portway-server"
)

// OperatingSystem identifies a supported client operating system.
type OperatingSystem string

const (
	// OperatingSystemDarwin identifies macOS.
	OperatingSystemDarwin OperatingSystem = "darwin"
	// OperatingSystemLinux identifies Linux.
	OperatingSystemLinux OperatingSystem = "linux"
	// OperatingSystemWindows identifies Windows.
	OperatingSystemWindows OperatingSystem = "windows"
)

// Architecture identifies a supported client CPU architecture.
type Architecture string

const (
	// ArchitectureAMD64 identifies the AMD64 architecture.
	ArchitectureAMD64 Architecture = "amd64"
	// ArchitectureARM64 identifies the ARM64 architecture.
	ArchitectureARM64 Architecture = "arm64"
)

// ServerIdentification declares the server product and release version.
type ServerIdentification struct {
	Product Product `json:"product"`
	Version string  `json:"version"`
}

// ClientIdentification declares the client product and runtime environment.
type ClientIdentification struct {
	Product  Product         `json:"product"`
	Version  string          `json:"version"`
	OS       OperatingSystem `json:"os"`
	Arch     Architecture    `json:"arch"`
	Hostname string          `json:"hostname"`
}

// ValidateServerIdentification validates a server identification payload.
func ValidateServerIdentification(identification ServerIdentification) error {
	if identification.Product != ProductServer {
		return fmt.Errorf("unexpected server product %q", identification.Product)
	}
	return validateIdentificationText("server version", identification.Version, maxVersionLength)
}

// ValidateClientIdentification validates a client identification payload.
func ValidateClientIdentification(identification ClientIdentification) error {
	if identification.Product != ProductClient {
		return fmt.Errorf("unexpected client product %q", identification.Product)
	}
	if err := validateIdentificationText(
		"client version",
		identification.Version,
		maxVersionLength,
	); err != nil {
		return err
	}
	switch identification.OS {
	case OperatingSystemDarwin, OperatingSystemLinux, OperatingSystemWindows:
	default:
		return fmt.Errorf("unsupported client operating system %q", identification.OS)
	}
	switch identification.Arch {
	case ArchitectureAMD64, ArchitectureARM64:
	default:
		return fmt.Errorf("unsupported client architecture %q", identification.Arch)
	}
	if identification.OS == OperatingSystemWindows &&
		identification.Arch == ArchitectureARM64 {
		return errors.New("unsupported client platform windows-arm64")
	}
	return validateIdentificationText(
		"client hostname",
		identification.Hostname,
		maxHostnameLength,
	)
}

func validateIdentificationText(name string, value string, maximumLength int) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len(value) > maximumLength {
		return fmt.Errorf("%s exceeds %d bytes", name, maximumLength)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s must be valid UTF-8", name)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not have leading or trailing whitespace", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s must not contain control characters", name)
		}
	}
	return nil
}
