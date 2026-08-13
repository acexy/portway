package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadClientRejectsOversizedConfigurationFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxConfigurationFileBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = LoadClient(path, false)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized configuration error = %v", err)
	}
}
