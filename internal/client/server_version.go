package client

import (
	"cmp"
	"regexp"
	"strings"
)

func (s *Service) logServerVersion(serverVersion string) {
	clientVersion := s.identification.Version
	fields := map[string]any{
		"event":          "server_version_reported",
		"client_version": clientVersion,
		"server_version": serverVersion,
	}
	comparison, comparable := compareReleaseVersions(clientVersion, serverVersion)
	if !comparable {
		s.logger.InfoWithFields("connected server version; version comparison skipped", fields)
		return
	}
	if comparison < 0 {
		s.logger.WarnWithFields("client version is older than server; consider upgrading client", nil, fields)
		return
	}
	s.logger.InfoWithFields("connected server version", fields)
}

// compareReleaseVersions accepts complete SemVer versions with an optional v prefix.
// Unknown build labels are informational and must never prevent a connection.
func compareReleaseVersions(clientVersion, serverVersion string) (int, bool) {
	const pattern = `^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`
	versionPattern := regexp.MustCompile(pattern)
	clientParts := versionPattern.FindStringSubmatch(clientVersion)
	serverParts := versionPattern.FindStringSubmatch(serverVersion)
	if clientParts == nil || serverParts == nil {
		return 0, false
	}
	for _, parts := range [][]string{clientParts, serverParts} {
		for _, identifier := range strings.Split(parts[4], ".") {
			if isVersionNumber(identifier) && len(identifier) > 1 && identifier[0] == '0' {
				return 0, false
			}
		}
	}
	for index := 1; index <= 3; index++ {
		if comparison := compareVersionNumbers(clientParts[index], serverParts[index]); comparison != 0 {
			return comparison, true
		}
	}
	clientPrerelease, serverPrerelease := clientParts[4], serverParts[4]
	if clientPrerelease == serverPrerelease {
		return 0, true
	}
	if clientPrerelease == "" {
		return 1, true
	}
	if serverPrerelease == "" {
		return -1, true
	}
	clientIdentifiers := strings.Split(clientPrerelease, ".")
	serverIdentifiers := strings.Split(serverPrerelease, ".")
	for index := 0; index < min(len(clientIdentifiers), len(serverIdentifiers)); index++ {
		clientIdentifier, serverIdentifier := clientIdentifiers[index], serverIdentifiers[index]
		clientNumeric, serverNumeric := isVersionNumber(clientIdentifier), isVersionNumber(serverIdentifier)
		comparison := strings.Compare(clientIdentifier, serverIdentifier)
		switch {
		case clientNumeric && serverNumeric:
			comparison = compareVersionNumbers(clientIdentifier, serverIdentifier)
		case clientNumeric:
			comparison = -1
		case serverNumeric:
			comparison = 1
		}
		if comparison != 0 {
			return comparison, true
		}
	}
	return cmp.Compare(len(clientIdentifiers), len(serverIdentifiers)), true
}

func isVersionNumber(identifier string) bool {
	if identifier == "" {
		return false
	}
	for _, character := range identifier {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func compareVersionNumbers(left, right string) int {
	// Validated numeric identifiers have no leading zeroes. Compare lengths first
	// to support arbitrarily large SemVer numbers without integer overflow.
	if comparison := cmp.Compare(len(left), len(right)); comparison != 0 {
		return comparison
	}
	return strings.Compare(left, right)
}
