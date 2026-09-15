//go:build linux || darwin

package vnet

import (
	"context"
	"os"
	"os/exec"
)

func platformOwnerID() int { return os.Getuid() }

func privilegedCommand(name string, arguments ...string) *exec.Cmd {
	return privilegedCommandContext(context.Background(), name, arguments...)
}

func privilegedCommandContext(ctx context.Context, name string, arguments ...string) *exec.Cmd {
	var command *exec.Cmd
	if os.Geteuid() == 0 {
		command = exec.CommandContext(ctx, name, arguments...)
	} else {
		sudoArguments := append([]string{name}, arguments...)
		if !interactiveTerminalAvailable() {
			sudoArguments = append([]string{"-n"}, sudoArguments...)
		}
		command = exec.CommandContext(ctx, "sudo", sudoArguments...)
	}
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command
}

func manifestPath() string {
	if platformRootGroup() == "wheel" {
		return "/Library/Application Support/Portway/vnetwork/portway0.json"
	}
	return "/var/lib/portway/vnetwork/portway0.json"
}
