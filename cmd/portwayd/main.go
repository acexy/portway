package main

import (
	"flag"
	"os"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/lifecycle"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/server"
)

func main() {
	configPath := flag.String("config", "server.yaml", "path to the server YAML configuration file")
	flag.Parse()

	log := logging.New("portwayd")

	configuration, err := config.LoadServer(*configPath, !configFlagWasSet())
	if err != nil {
		log.Error("failed to load server configuration", err)
		os.Exit(1)
	}
	if err := logging.EnableConsole(configuration.LogLevel); err != nil {
		log.Error("failed to configure logging", err)
		os.Exit(1)
	}

	token, generated, err := config.EnsureServerToken(&configuration)
	if err != nil {
		log.Error("failed to generate server token", err)
		os.Exit(1)
	}
	if generated {
		log.InfoWithField("generated server authentication token", "token", token)
	}

	service := server.NewService(log, configuration)
	if err := lifecycle.Run(service); err != nil {
		log.Error("server exited", err)
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
