package main

import (
	"fmt"
	"io"
	"os"

	"github.com/acexy/portway/internal/buildinfo"
	"github.com/acexy/portway/internal/cli"
	"github.com/acexy/portway/internal/client"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/config/gen"
	"github.com/acexy/portway/internal/lifecycle"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/vnet"
)

func main() {
	if handled, err := vnet.RunPlatformHelper(os.Args[1:]); handled {
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "portway VNet helper: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout io.Writer, stderr io.Writer) int {
	commands := []cli.Command{
		{
			Name:    "run",
			Usage:   "run [config]",
			Summary: "Start the Portway client",
			Execute: runClientCommand,
		},
		{
			Name:    "gen",
			Summary: "Generate client resources",
			Subcommands: []cli.Command{{
				Name:    "config",
				Usage:   "config [full]",
				Summary: "Generate client.yaml in the current directory",
				Options: []cli.Option{{
					Usage:       "full",
					Description: "Generate the complete annotated configuration",
				}},
				Execute: runGenerateClientConfiguration,
			}},
		},
	}
	if vnet.NetworkStatusSupported() || vnet.NetworkUninstallSupported() {
		subcommands := make([]cli.Command, 0, 2)
		if vnet.NetworkStatusSupported() {
			subcommands = append(subcommands, cli.Command{
				Name: "status", Summary: "Inspect the owned portway0 network", Execute: runClientVNetworkStatus,
			})
		}
		if vnet.NetworkUninstallSupported() {
			subcommands = append(subcommands, cli.Command{
				Name: "uninstall", Summary: "Safely remove the owned portway0 network", Execute: runUninstallVNetwork,
			})
		}
		commands = append(commands, cli.Command{
			Name: "vnetwork", Summary: "Manage the Portway virtual network",
			Subcommands: subcommands,
		})
	}
	application := cli.Application{
		Name:        "portway",
		Title:       "Portway Client",
		Description: "Lightweight, secure, and stable network connectivity through Proxy, Forward, and VNet modes.",
		Version:     buildinfo.Current(),
		Commands:    commands,
	}
	return application.Run(arguments, stdout, stderr)
}

func runClientVNetworkStatus(arguments []string, stdout io.Writer, stderr io.Writer) int {
	if !vnet.NetworkStatusSupported() {
		_, _ = io.WriteString(stderr, "portway vnetwork: status is unavailable on this platform\n")
		return 1
	}
	if len(arguments) != 0 {
		_, _ = io.WriteString(stderr, "portway vnetwork status: no arguments are allowed\n")
		return 2
	}
	status, err := vnet.InspectNetwork()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "portway vnetwork status: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "installed: %t\ninterface: %s\ncidr: %s\nlocal_ip: %s\n", status.Installed, status.InterfaceName, status.CIDR, status.LocalIP)
	return 0
}

func runUninstallVNetwork(arguments []string, stdout io.Writer, stderr io.Writer) int {
	if !vnet.NetworkUninstallSupported() {
		_, _ = io.WriteString(stderr, "portway vnetwork: manual management is unavailable on this platform; VNet is managed automatically during run\n")
		return 1
	}
	if len(arguments) != 0 {
		_, _ = io.WriteString(stderr, "portway vnetwork uninstall: no arguments are allowed\n")
		return 2
	}
	result, err := vnet.UninstallNetworkAuthorized()
	if err != nil {
		_, _ = io.WriteString(stderr, "portway vnetwork uninstall: "+result+": "+err.Error()+"\n")
		return 1
	}
	_, _ = io.WriteString(stdout, result+"\n")
	return 0
}

func runGenerateClientConfiguration(
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	full, err := gen.ParseMode(arguments)
	if err != nil {
		_, _ = io.WriteString(stderr, "portway gen config: "+err.Error()+"\n")
		return 2
	}
	path, err := gen.Generate(gen.TargetClient, full)
	if err != nil {
		_, _ = io.WriteString(stderr, "portway gen config: "+err.Error()+"\n")
		return 1
	}
	_, _ = io.WriteString(stdout, "Created client configuration: "+path+"\n")
	return 0
}

func runClientCommand(
	arguments []string,
	_ io.Writer,
	stderr io.Writer,
) int {
	configPath, valid := clientConfigurationPath(arguments)
	if !valid {
		_, _ = io.WriteString(stderr, "portway run: at most one configuration file is allowed\n")
		return 2
	}

	log := logging.New("client")

	configuration, err := config.LoadClient(configPath, false)
	if err != nil {
		log.Error("failed to load client configuration", err)
		return 1
	}
	if exitCode, relaunched, err := vnet.ElevateCurrentProcess(); err != nil {
		log.Error("failed to obtain Windows administrator authorization", err)
		return 1
	} else if relaunched {
		return exitCode
	}
	if err := logging.EnableConsole(configuration.LogLevel); err != nil {
		log.Error("failed to configure logging", err)
		return 1
	}
	log.InfoWithFields("client configuration loaded", map[string]any{
		"event":       "configuration_loaded",
		"config_file": configPath,
		"log_level":   configuration.LogLevel,
		"transport":   configuration.Transport.Type,
		"proxy_count": len(configuration.Proxies),
	})
	clientID, generated, err := config.EnsureClientID(&configuration)
	if err != nil {
		log.Error("failed to generate client ID", err)
		return 1
	}
	if generated {
		log.InfoWithField("generated process client ID", "client_id", clientID)
	}

	service := client.NewService(log, configuration)
	if err := lifecycle.Run(service); err != nil {
		log.Error("client exited", err)
		return 1
	}
	return 0
}

func clientConfigurationPath(arguments []string) (string, bool) {
	switch len(arguments) {
	case 0:
		return "client.yaml", true
	case 1:
		return arguments[0], true
	default:
		return "", false
	}
}
