//go:build darwin

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDarwinVNetworkUninstallReportsAutomaticManagement(t *testing.T) {
	var stderr bytes.Buffer
	if code := runUninstallVNetwork(nil, &bytes.Buffer{}, &stderr); code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "managed automatically during run") {
		t.Fatalf("unexpected error: %s", stderr.String())
	}
}
