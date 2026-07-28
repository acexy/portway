package main

import (
	"flag"
	"os"

	"github.com/acexy/portway/internal/client"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/lifecycle"
	"github.com/acexy/portway/internal/logging"
)

func main() {
	configPath := flag.String("config", "client.yaml", "path to the client YAML configuration file")
	flag.Parse()

	log := logging.New("portway")

	configuration, err := config.LoadClient(*configPath, !configFlagWasSet())
	if err != nil {
		log.Error("failed to load client configuration", err)
		os.Exit(1)
	}
	if err := logging.EnableConsole(configuration.LogLevel); err != nil {
		log.Error("failed to configure logging", err)
		os.Exit(1)
	}
	clientID, generated, err := config.EnsureClientID(&configuration)
	if err != nil {
		log.Error("failed to generate client ID", err)
		os.Exit(1)
	}
	if generated {
		log.InfoWithField("generated process client ID", "client_id", clientID)
	}

	service := client.NewService(log, configuration)
	if err := lifecycle.Run(service); err != nil {
		log.Error("client exited", err)
		os.Exit(1)
	}
}

func configFlagWasSet() bool {
	configured := false
	flag.Visit(func(currentFlag *flag.Flag) {
		if currentFlag.Name == "config" {
			configured = true
		}
	})
	return configured
}
