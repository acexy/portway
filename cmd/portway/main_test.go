package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/transport"
	"github.com/acexy/portway/internal/vnet/system"
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
		"Lightweight, secure, and stable network connectivity through Proxy, Forward, and VNet modes.",
		"portway <command> [options]",
		"run [config]",
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

func TestRunShowsOnlySupportedClientVNetworkCommands(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"help"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d", exitCode)
	}
	hasVNetwork := strings.Contains(stdout.String(), "vnetwork uninstall")
	if hasVNetwork != system.NetworkUninstallSupported() {
		t.Fatalf("stdout = %q, vnetwork visibility = %t", stdout.String(), hasVNetwork)
	}
	hasStatus := strings.Contains(stdout.String(), "vnetwork status")
	if hasStatus != system.NetworkStatusSupported() {
		t.Fatalf("stdout = %q, status visibility = %t", stdout.String(), hasStatus)
	}
	if strings.Contains(stdout.String(), "vnetwork install") || strings.Contains(stdout.String(), "vnetwork repair") {
		t.Fatalf("stdout exposes unsupported client VNet commands: %q", stdout.String())
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

func TestRunClientAllowsAtMostOneConfigurationFile(t *testing.T) {
	for _, arguments := range [][]string{
		{"run", "client.yaml", "extra.yaml"},
		{"run", "--config", "client.yaml"},
	} {
		var stderr bytes.Buffer
		exitCode := run(arguments, io.Discard, &stderr)
		if exitCode != 2 {
			t.Fatalf("run(%v) exit code = %d, want 2", arguments, exitCode)
		}
		if !strings.Contains(stderr.String(), "at most one configuration file is allowed") {
			t.Fatalf("run(%v) stderr = %q", arguments, stderr.String())
		}
	}
}

func TestRunClientUsesDefaultConfigurationFile(t *testing.T) {
	path, valid := clientConfigurationPath(nil)
	if !valid || path != "client.yaml" {
		t.Fatalf("clientConfigurationPath(nil) = %q, %t", path, valid)
	}

	workingDirectory := t.TempDir()
	previousDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previousDirectory) })

	exitCode := run([]string{"run"}, io.Discard, io.Discard)
	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want configuration load failure", exitCode)
	}
}

func TestFinishClientRunElevatesOnlyForVNetAuthorization(t *testing.T) {
	for _, test := range []struct {
		name       string
		runError   error
		relaunched bool
		childCode  int
		elevateErr error
		wantCode   int
		wantCalls  int
	}{
		{name: "normal shutdown"},
		{name: "ordinary failure", runError: errors.New("connection failed"), wantCode: 1},
		{name: "VNet authorization", runError: transport.Permanent(system.ErrElevationRequired), relaunched: true, childCode: 7, wantCode: 7, wantCalls: 1},
		{name: "UAC rejected", runError: system.ErrElevationRequired, elevateErr: errors.New("authorization canceled"), wantCode: 1, wantCalls: 1},
		{name: "no restart", runError: system.ErrElevationRequired, wantCode: 1, wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			code := finishClientRun(test.runError, logging.New("test"), func() (int, bool, error) {
				calls++
				return test.childCode, test.relaunched, test.elevateErr
			})
			if code != test.wantCode || calls != test.wantCalls {
				t.Fatalf("exit=%d calls=%d, want exit=%d calls=%d", code, calls, test.wantCode, test.wantCalls)
			}
		})
	}
}
