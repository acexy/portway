package configgenerator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acexy/portway/internal/config"
)

func TestGeneratedConfigurationsAreValidAndRefuseOverwrite(t *testing.T) {
	testCases := []struct {
		name   string
		target Target
		full   bool
		file   string
		load   func(string) error
	}{
		{
			name: "minimal client", target: TargetClient, file: "client.yaml",
			load: func(path string) error { _, err := config.LoadClient(path, false); return err },
		},
		{
			name: "full client", target: TargetClient, full: true, file: "client.yaml",
			load: func(path string) error { _, err := config.LoadClient(path, false); return err },
		},
		{
			name: "minimal server", target: TargetServer, file: "server.yaml",
			load: func(path string) error { _, err := config.LoadServer(path, false); return err },
		},
		{
			name: "full server", target: TargetServer, full: true, file: "server.yaml",
			load: func(path string) error { _, err := config.LoadServer(path, false); return err },
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			workingDirectory := t.TempDir()
			previousDirectory, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chdir(workingDirectory); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chdir(previousDirectory) })

			path, err := Generate(testCase.target, testCase.full)
			if err != nil {
				t.Fatal(err)
			}
			if path != testCase.file {
				t.Fatalf("generated path = %q, want %q", path, testCase.file)
			}
			content, err := os.ReadFile(filepath.Join(workingDirectory, path))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(content), "https://github.com/acexy/portway/tree/main/config") {
				t.Fatal("generated configuration does not link to the full reference")
			}
			if err := testCase.load(path); err != nil {
				t.Fatalf("generated configuration is invalid: %v", err)
			}
			if _, err := Generate(testCase.target, testCase.full); err == nil {
				t.Fatal("existing configuration was overwritten")
			}
		})
	}
}
