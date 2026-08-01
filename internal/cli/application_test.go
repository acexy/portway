package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/acexy/portway/internal/buildinfo"
)

func TestApplicationWithoutArgumentsPrintsHelp(t *testing.T) {
	application := testApplication()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := application.Run(nil, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("Run() exit code = %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "Usage:\n  portway <command>") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestApplicationDispatchesCommand(t *testing.T) {
	application := testApplication()
	called := false
	application.Commands[0].Execute = func(
		arguments []string,
		_ io.Writer,
		_ io.Writer,
	) int {
		called = len(arguments) == 1 && arguments[0] == "--config=test.yaml"
		return 7
	}

	exitCode := application.Run(
		[]string{"run", "--config=test.yaml"},
		io.Discard,
		io.Discard,
	)

	if exitCode != 7 || !called {
		t.Fatalf("Run() exit code = %d, called = %t", exitCode, called)
	}
}

func TestApplicationRejectsUnknownCommand(t *testing.T) {
	application := testApplication()
	var stderr bytes.Buffer

	exitCode := application.Run([]string{"unknown"}, io.Discard, &stderr)

	if exitCode != 2 {
		t.Fatalf("Run() exit code = %d", exitCode)
	}
	if !strings.Contains(stderr.String(), `unknown command "unknown"`) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestApplicationColorCanBeForced(t *testing.T) {
	application := testApplication()
	application.Color = ColorAlways
	var stdout bytes.Buffer

	application.WriteHelp(&stdout)

	if !strings.Contains(stdout.String(), "\x1b[") {
		t.Fatalf("stdout = %q, want ANSI style", stdout.String())
	}
}

func TestApplicationVersionPrintsOnlyVersion(t *testing.T) {
	application := testApplication()
	application.Version = buildinfo.Info{
		Version:   "v1.2.3",
		Commit:    "1234567890abcdef",
		BuildTime: "2026-07-29T12:00:00Z",
		GoVersion: "go1.25.8",
		Modified:  true,
	}
	var stdout bytes.Buffer

	application.WriteVersion(&stdout)

	expected := "version: v1.2.3\ncore-protocol: 1\n"
	if stdout.String() != expected {
		t.Fatalf("stdout = %q, want %q", stdout.String(), expected)
	}
}

func testApplication() Application {
	return Application{
		Name:        "portway",
		Title:       "Portway Client",
		Description: "Secure reverse tunneling client",
		Version:     buildinfo.Info{Version: "development"},
		Color:       ColorNever,
		Commands: []Command{
			{
				Name:    "run",
				Summary: "Start the client",
				Execute: func([]string, io.Writer, io.Writer) int { return 0 },
			},
		},
	}
}
