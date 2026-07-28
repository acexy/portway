package logging

import (
	"testing"

	"github.com/acexy/golang-toolkit/logger"
	"github.com/acexy/portway/internal/config"
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
