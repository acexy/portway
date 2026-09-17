//go:build !linux && !darwin

package vnet

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

func platformOwnerID() int { return -1 }

func privilegedCommand(name string, arguments ...string) *exec.Cmd {
	return privilegedCommandContext(context.Background(), name, arguments...)
}

func privilegedCommandContext(ctx context.Context, name string, arguments ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command
}

func manifestPath() string {
	if programData := os.Getenv("ProgramData"); programData != "" {
		return filepath.Join(programData, "Portway", "vnetwork", "portway0.json")
	}
	return filepath.Join(os.TempDir(), "Portway", "vnetwork", "portway0.json")
}
