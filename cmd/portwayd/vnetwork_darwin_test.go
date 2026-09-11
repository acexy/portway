//go:build darwin

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDarwinVNetworkCommandsReportAutomaticManagement(t *testing.T) {
	commands := []func([]string, *bytes.Buffer, *bytes.Buffer) int{
		func(arguments []string, stdout *bytes.Buffer, stderr *bytes.Buffer) int {
			return runVNetworkStatus(arguments, stdout, stderr)
		},
		func(arguments []string, stdout *bytes.Buffer, stderr *bytes.Buffer) int {
			return runVNetworkInstall(arguments, stdout, stderr)
		},
		func(arguments []string, stdout *bytes.Buffer, stderr *bytes.Buffer) int {
			return runVNetworkRepair(arguments, stdout, stderr)
		},
		func(arguments []string, stdout *bytes.Buffer, stderr *bytes.Buffer) int {
			return runServerVNetworkUninstall(arguments, stdout, stderr)
		},
	}
	for index, command := range commands {
		var stderr bytes.Buffer
		if code := command(nil, &bytes.Buffer{}, &stderr); code != 1 {
			t.Fatalf("command %d: expected exit code 1, got %d", index, code)
		}
		if !strings.Contains(stderr.String(), "managed automatically during run") {
			t.Fatalf("command %d: unexpected error: %s", index, stderr.String())
		}
	}
}
