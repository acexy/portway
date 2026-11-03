package client

import (
	"io"
	"strings"
	"testing"

	"github.com/acexy/golang-toolkit/logger"

	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

func TestCompareReleaseVersions(t *testing.T) {
	t.Parallel()

	ordered := []string{
		"v1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
		"1.0.1", "1.9.0", "1.10.0", "2.0.0", "999999999999999999999.0.0",
	}
	for index, version := range ordered {
		if comparison, valid := compareReleaseVersions(version, version); !valid || comparison != 0 {
			t.Fatalf("equal version %q: comparison=%d valid=%t", version, comparison, valid)
		}
		for _, newer := range ordered[index+1:] {
			if comparison, valid := compareReleaseVersions(version, newer); !valid || comparison != -1 {
				t.Fatalf("%q < %q: comparison=%d valid=%t", version, newer, comparison, valid)
			}
			if comparison, valid := compareReleaseVersions(newer, version); !valid || comparison != 1 {
				t.Fatalf("%q > %q: comparison=%d valid=%t", newer, version, comparison, valid)
			}
		}
	}
	for _, pair := range [][2]string{
		{"v1.2.3+001", "1.2.3+build.456"},
		{"v1.2.3-rc.1+build", "1.2.3-rc.1"},
		{"1.2.3-01a", "v1.2.3-01a+001"},
	} {
		if comparison, valid := compareReleaseVersions(pair[0], pair[1]); !valid || comparison != 0 {
			t.Fatalf("equivalent versions %v: comparison=%d valid=%t", pair, comparison, valid)
		}
	}
	for _, invalid := range []string{
		"", "development", "v1", "1.2", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01",
		"1.2.3-rc.01", "1.2.3-", "1.2.3+", "1.2.3-a..b", "1.2.3+a..b",
		"1.2.3+a+b", "1.2.3_rc1", "V1.2.3", " 1.2.3", "1.2.3\n", "1.2.3-测试",
	} {
		for _, pair := range [][2]string{{invalid, "v2.0.0"}, {"v2.0.0", invalid}} {
			if _, valid := compareReleaseVersions(pair[0], pair[1]); valid {
				t.Errorf("accepted invalid version pair %q", pair)
			}
		}
	}
}

func TestLogServerVersion(t *testing.T) {
	activeLogger := logger.Logrus()
	originalOutput, originalLevel := activeLogger.Out, activeLogger.GetLevel()
	originalHooks := activeLogger.ReplaceHooks(make(logrus.LevelHooks))
	hook := logrustest.NewLocal(activeLogger)
	activeLogger.SetOutput(io.Discard)
	activeLogger.SetLevel(logrus.InfoLevel)
	t.Cleanup(func() {
		activeLogger.SetOutput(originalOutput)
		activeLogger.SetLevel(originalLevel)
		activeLogger.ReplaceHooks(originalHooks)
	})

	for _, testCase := range []struct {
		clientVersion string
		serverVersion string
		level         logrus.Level
		skipped       bool
	}{
		{"v1.2.0", "v1.3.0", logrus.WarnLevel, false},
		{"v1.3.0", "v1.3.0", logrus.InfoLevel, false},
		{"v1.4.0", "v1.3.0", logrus.InfoLevel, false},
		{"v1.3.0-rc.1", "v1.3.0", logrus.WarnLevel, false},
		{"development", "v1.3.0", logrus.InfoLevel, true},
		{"v1.3.0", "unknown", logrus.InfoLevel, true},
	} {
		hook.Reset()
		service := &Service{
			logger:         logging.New("client"),
			identification: protocol.ClientIdentification{Version: testCase.clientVersion},
		}
		service.logServerVersion(testCase.serverVersion)
		entries := hook.AllEntries()
		if len(entries) != 1 {
			t.Fatalf("got %d version notices, want 1", len(entries))
		}
		entry := entries[0]
		if entry.Level != testCase.level ||
			entry.Data["client_version"] != testCase.clientVersion ||
			entry.Data["server_version"] != testCase.serverVersion ||
			entry.Data["event"] != "server_version_reported" {
			t.Fatalf("unexpected version notice: %+v", entry)
		}
		if strings.Contains(entry.Message, "comparison skipped") != testCase.skipped {
			t.Fatalf("unexpected comparison message: %s", entry.Message)
		}
		if entry.Level == logrus.WarnLevel && !strings.Contains(entry.Message, "upgrading client") {
			t.Fatalf("missing upgrade advice: %s", entry.Message)
		}
	}
}
