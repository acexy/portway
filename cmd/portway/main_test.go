package main

import (
	"bytes"
	"os"
	"path/filepath"
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
		"gen config [full]",
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

func TestRunGenerateClientConfiguration(t *testing.T) {
	workingDirectory := t.TempDir()
	previousDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previousDirectory) })

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"gen", "config"}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	content, err := os.ReadFile(filepath.Join(workingDirectory, "client.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "Minimal Portway client configuration") {
		t.Fatalf("client.yaml = %q", content)
	}
}

func TestRunVersionPrintsClientVersion(t *testing.T) {
	var stdout bytes.Buffer

	exitCode := run([]string{"version"}, &stdout, &bytes.Buffer{})

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d", exitCode)
	}
	expected := "version: development\ncore-protocol: 1\n"
	if stdout.String() != expected {
		t.Fatalf("stdout = %q, want %q", stdout.String(), expected)
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
