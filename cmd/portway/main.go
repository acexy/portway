package main

import (
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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout io.Writer, stderr io.Writer) int {
	application := cli.Application{
		Name:        "portway",
		Title:       "Portway Client",
		Description: "Secure reverse tunneling client",
		Version:     buildinfo.Current(),
		Commands: []cli.Command{
			{
				Name:    "run",
				Usage:   "run [FILE]",
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
			{
				Name: "vnetwork", Summary: "Manage the Portway virtual network",
				Subcommands: []cli.Command{{
					Name: "uninstall", Summary: "Safely remove the owned portway0 network",
					Execute: runUninstallVNetwork,
				}},
			},
		},
	}
	return application.Run(arguments, stdout, stderr)
}

func runUninstallVNetwork(arguments []string, stdout io.Writer, stderr io.Writer) int {
	if len(arguments) != 0 {
		_, _ = io.WriteString(stderr, "portway vnetwork uninstall: no arguments are allowed\n")
		return 2
	}
	result, err := vnet.UninstallNetwork()
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
