// Package buildinfo provides version metadata for Portway binaries.
package buildinfo

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// These values may be injected by release builds with -ldflags -X.
var (
	Version   string
	Commit    string
	BuildTime string
)

// Info describes one Portway binary build.
type Info struct {
	Version   string
	Commit    string
	BuildTime string
	GoVersion string
	Modified  bool
}

// Current returns injected release metadata and falls back to the build
// information embedded by the Go toolchain.
func Current() Info {
	info := Info{
		Version:   normalizedVersion(Version),
		Commit:    Commit,
		BuildTime: BuildTime,
		GoVersion: runtime.Version(),
	}
	build, available := debug.ReadBuildInfo()
	if !available {
		return info
	}
	if info.Version == "development" {
		info.Version = normalizedVersion(build.Main.Version)
	}
	for _, setting := range build.Settings {
		switch setting.Key {
		case "vcs.revision":
			if info.Commit == "" {
				info.Commit = setting.Value
			}
		case "vcs.modified":
			info.Modified = setting.Value == "true"
		}
	}
	return info
}

// ShortCommit returns a compact revision suitable for terminal output.
func (info Info) ShortCommit() string {
	const shortCommitLength = 12
	if len(info.Commit) <= shortCommitLength {
		return info.Commit
	}
	return info.Commit[:shortCommitLength]
}

func normalizedVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" || version == "(devel)" {
		return "development"
	}
	return version
}
