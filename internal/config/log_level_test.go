package config

import "testing"

func TestDefaultConfigurationsUseInfoLogLevel(t *testing.T) {
	t.Parallel()

	if DefaultClient().LogLevel != LogLevelInfo {
		t.Fatalf("unexpected client default log level %q", DefaultClient().LogLevel)
	}
	if DefaultServer().LogLevel != LogLevelInfo {
		t.Fatalf("unexpected server default log level %q", DefaultServer().LogLevel)
	}
}

func TestValidateLogLevel(t *testing.T) {
	t.Parallel()

	validLevels := []LogLevel{
		LogLevelTrace,
		LogLevelDebug,
		LogLevelInfo,
		LogLevelWarn,
		LogLevelError,
	}
	for _, logLevel := range validLevels {
		if err := validateLogLevel(logLevel); err != nil {
			t.Fatalf("valid log level %q was rejected: %v", logLevel, err)
		}
	}

	if err := validateLogLevel("verbose"); err == nil {
		t.Fatal("invalid log level was accepted")
	}
}
