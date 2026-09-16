//go:build windows && amd64

package vnet

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWindowsCommandLinePreservesArguments(t *testing.T) {
	arguments := []string{"run", `C:\Program Files\Portway\client.yaml`, `value"with quote`, ""}
	want := `run "C:\Program Files\Portway\client.yaml" "value\"with quote" ""`
	if got := windowsCommandLine(arguments); got != want {
		t.Fatalf("windowsCommandLine() = %q, want %q", got, want)
	}
}

func TestReadWindowsUninstallResponse(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	tests := []struct {
		name       string
		response   windowsUninstallResponse
		exitCode   int
		wantResult string
		wantError  string
	}{
		{name: "success", response: windowsUninstallResponse{Nonce: nonce, Result: "Removed"}, wantResult: "Removed"},
		{name: "operation error", response: windowsUninstallResponse{Nonce: nonce, Result: "InUse", Error: "VNet network is in use"}, wantResult: "InUse", wantError: "VNet network is in use"},
		{name: "wrong nonce", response: windowsUninstallResponse{Nonce: strings.Repeat("b", 64), Result: "Removed"}, wantResult: "PermissionDenied", wantError: "authentication failed"},
		{name: "helper failure", response: windowsUninstallResponse{Nonce: nonce, Result: "Removed"}, exitCode: 1, wantResult: "PermissionDenied", wantError: "exited with code 1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var data bytes.Buffer
			if err := json.NewEncoder(&data).Encode(test.response); err != nil {
				t.Fatal(err)
			}
			result, err := readWindowsUninstallResponse(&data, nonce, test.exitCode)
			if result != test.wantResult {
				t.Fatalf("result = %q, want %q", result, test.wantResult)
			}
			if test.wantError == "" && err != nil {
				t.Fatalf("error = %v", err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}
