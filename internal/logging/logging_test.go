package logging

import (
	"strings"
	"testing"
	"time"

	"github.com/acexy/golang-toolkit/logger"
	"github.com/acexy/portway/internal/config"
	"github.com/sirupsen/logrus"
)

func TestToolkitLogLevel(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		configured config.LogLevel
		expected   logger.Level
	}{
		{configured: config.LogLevelTrace, expected: logger.TraceLevel},
		{configured: config.LogLevelDebug, expected: logger.DebugLevel},
		{configured: config.LogLevelInfo, expected: logger.InfoLevel},
		{configured: config.LogLevelWarn, expected: logger.WarnLevel},
		{configured: config.LogLevelError, expected: logger.ErrorLevel},
	}
	for _, testCase := range testCases {
		actual, err := toolkitLogLevel(testCase.configured)
		if err != nil {
			t.Fatalf("map log level %q: %v", testCase.configured, err)
		}
		if actual != testCase.expected {
			t.Fatalf(
				"unexpected toolkit level for %q: got %d, want %d",
				testCase.configured,
				actual,
				testCase.expected,
			)
		}
	}
}

func TestConsoleFormatterUsesStableReadableLayout(t *testing.T) {
	entry := &logrus.Entry{
		Logger:  logrus.New(),
		Time:    time.Date(2026, time.July, 31, 22, 22, 56, 123000000, time.Local),
		Level:   logrus.WarnLevel,
		Message: "control session disconnected",
		Data: logrus.Fields{
			"component":      "session",
			"session_id":     "session-one",
			"client_id":      "client-one",
			"event":          "control_session_disconnected",
			"remote_address": "192.0.2.1:7000",
			"error":          "connection reset by peer",
		},
	}
	formatted, err := (consoleFormatter{}).Format(entry)
	if err != nil {
		t.Fatal(err)
	}
	actual := string(formatted)
	wantParts := []string{
		"2026-07-31 22:22:56.123 WARN  session",
		"control session disconnected",
		"event=control_session_disconnected",
		"client_id=client-one session_id=session-one",
		"remote_address=192.0.2.1:7000",
		`error="connection reset by peer"`,
	}
	for _, part := range wantParts {
		if !strings.Contains(actual, part) {
			t.Fatalf("formatted log %q does not contain %q", actual, part)
		}
	}
}

func TestWithComponentPreservesContextWithoutMutatingParent(t *testing.T) {
	parent := New("server").WithFields(map[string]any{
		"client_id":  "client-one",
		"session_id": "session-one",
	})
	child := parent.WithComponent("session")

	if parent.component != "server" {
		t.Fatalf("parent component changed to %q", parent.component)
	}
	if child.component != "session" {
		t.Fatalf("child component = %q", child.component)
	}
	if child.fields["client_id"] != "client-one" ||
		child.fields["session_id"] != "session-one" {
		t.Fatalf("child fields = %#v", child.fields)
	}
}
