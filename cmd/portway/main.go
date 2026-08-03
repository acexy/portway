package main

import (
	"flag"
	"io"
	"os"

	"github.com/acexy/portway/internal/buildinfo"
	"github.com/acexy/portway/internal/cli"
	"github.com/acexy/portway/internal/client"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/lifecycle"
	"github.com/acexy/portway/internal/logging"
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
				Usage:   "run [--config FILE]",
				Summary: "Start the Portway client",
				Options: []cli.Option{
					{
						Usage:       "--config FILE",
						Description: "Client YAML configuration (default: client.yaml)",
					},
				},
				Execute: runClientCommand,
			},
		},
	}
	return application.Run(arguments, stdout, stderr)
}

func runClientCommand(
	arguments []string,
	_ io.Writer,
	stderr io.Writer,
) int {
	flags := flag.NewFlagSet("portway run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String(
		"config",
		"client.yaml",
		"path to the client YAML configuration file",
	)
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = io.WriteString(stderr, "portway run: unexpected arguments\n")
		return 2
	}

	log := logging.New("client")

	configuration, err := config.LoadClient(*configPath, !configFlagWasSet(flags))
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
		"config_file": *configPath,
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

func configFlagWasSet(flags *flag.FlagSet) bool {
	configured := false
	flags.Visit(func(currentFlag *flag.Flag) {
		if currentFlag.Name == "config" {
			configured = true
		}
	})
	return configured
}
