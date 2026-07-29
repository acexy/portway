package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunWithoutArgumentsPrintsClientHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run(nil, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d", exitCode)
	}
	for _, expected := range []string{
		"Portway Client",
		"portway <command> [options]",
		"run",
		"version",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), expected)
		}
	}
	if strings.Contains(stdout.String(), "\x1b[") {
		t.Fatalf("redirected stdout contains ANSI styles: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunVersionPrintsClientVersion(t *testing.T) {
	var stdout bytes.Buffer

	exitCode := run([]string{"version"}, &stdout, &bytes.Buffer{})

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "portway ") ||
		!strings.Contains(stdout.String(), "Go:") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunRejectsUnknownClientCommand(t *testing.T) {
	var stderr bytes.Buffer

	exitCode := run([]string{"unknown"}, &bytes.Buffer{}, &stderr)

	if exitCode != 2 {
		t.Fatalf("run() exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), `unknown command "unknown"`) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
