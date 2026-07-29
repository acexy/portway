package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/acexy/portway/internal/buildinfo"
	"github.com/acexy/portway/internal/certificate"
	"github.com/acexy/portway/internal/cli"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/lifecycle"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/server"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout io.Writer, stderr io.Writer) int {
	application := cli.Application{
		Name:        "portwayd",
		Title:       "Portway Server",
		Description: "Secure reverse tunneling server",
		Version:     buildinfo.Current(),
		Commands: []cli.Command{
			{
				Name:    "run",
				Usage:   "run [--config FILE]",
				Summary: "Start the Portway server",
				Options: []cli.Option{
					{
						Usage:       "--config FILE",
						Description: "Server YAML configuration (default: server.yaml)",
					},
				},
				Execute: runServerCommand,
			},
			{
				Name:    "cert",
				Usage:   "cert generate [options]",
				Summary: "Generate an internal CA and server certificate",
				Options: []cli.Option{
					{
						Usage:       "generate",
						Description: "Create a root CA and QUIC server certificate",
					},
					{
						Usage:       "--output-dir DIR",
						Description: "Certificate output directory (default: certs)",
					},
					{
						Usage:       "--server-name NAME",
						Description: "Server DNS SAN; may be repeated",
					},
					{
						Usage:       "--ip ADDRESS",
						Description: "Server IP SAN; may be repeated",
					},
				},
				Execute: runCertificate,
			},
		},
	}
	return application.Run(arguments, stdout, stderr)
}

func runCertificate(
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	if len(arguments) == 2 &&
		arguments[0] == "generate" &&
		(arguments[1] == "-h" || arguments[1] == "--help") {
		writeCertificateGenerateHelp(stdout)
		return 0
	}
	if err := runCertificateCommand(arguments, stdout, stderr); err != nil {
		_, _ = fmt.Fprintf(stderr, "portwayd cert: %v\n", err)
		return 1
	}
	return 0
}

func runServerCommand(
	arguments []string,
	_ io.Writer,
	stderr io.Writer,
) int {
	flags := flag.NewFlagSet("portwayd run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String(
		"config",
		"server.yaml",
		"path to the server YAML configuration file",
	)
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "portwayd run: unexpected arguments: %v\n", flags.Args())
		return 2
	}
	configured := false
	flags.Visit(func(currentFlag *flag.Flag) {
		if currentFlag.Name == "config" {
			configured = true
		}
	})

	log := logging.New("portwayd")

	configuration, err := config.LoadServer(*configPath, !configured)
	if err != nil {
		log.Error("failed to load server configuration", err)
		return 1
	}
	if err := logging.EnableConsole(configuration.LogLevel); err != nil {
		log.Error("failed to configure logging", err)
		return 1
	}

	token, generated, err := config.EnsureServerToken(&configuration)
	if err != nil {
		log.Error("failed to generate server token", err)
		return 1
	}
	if generated {
		log.InfoWithField("generated server authentication token", "token", token)
	}

	service := server.NewService(log, configuration)
	if err := lifecycle.Run(service); err != nil {
		log.Error("server exited", err)
		return 1
	}
	return 0
}

func runCertificateCommand(
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
) error {
	if len(arguments) == 0 || arguments[0] != "generate" {
		return errorsNewCertificateUsage()
	}

	flags := flag.NewFlagSet("portwayd cert generate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outputDirectory := flags.String(
		"output-dir",
		"certs",
		"directory for generated certificate files",
	)
	var serverNames stringValues
	var ipAddressValues stringValues
	flags.Var(
		&serverNames,
		"server-name",
		"DNS name in the server certificate SAN; may be repeated",
	)
	flags.Var(
		&ipAddressValues,
		"ip",
		"IP address in the server certificate SAN; may be repeated",
	)
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}

	ipAddresses := make([]net.IP, 0, len(ipAddressValues))
	for _, value := range ipAddressValues {
		address := net.ParseIP(value)
		if address == nil {
			return fmt.Errorf("invalid IP address %q", value)
		}
		ipAddresses = append(ipAddresses, address)
	}
	files, err := certificate.Generate(certificate.Options{
		OutputDirectory: *outputDirectory,
		ServerNames:     append([]string(nil), serverNames...),
		IPAddresses:     ipAddresses,
	})
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(stdout, "Created root CA certificate: %s\n", files.RootCACertificate)
	_, _ = fmt.Fprintf(stdout, "Created root CA private key: %s\n", files.RootCAKey)
	_, _ = fmt.Fprintf(stdout, "Created server certificate: %s\n", files.ServerCertificate)
	_, _ = fmt.Fprintf(stdout, "Created server private key: %s\n", files.ServerKey)
	return nil
}

func writeCertificateGenerateHelp(writer io.Writer) {
	_, _ = io.WriteString(
		writer,
		"Generate an internal CA and QUIC server certificate\n\n"+
			"Usage:\n"+
			"  portwayd cert generate [options]\n\n"+
			"Options:\n"+
			"  --output-dir DIR         Certificate output directory (default: certs)\n"+
			"  --server-name NAME       Server DNS SAN; may be repeated\n"+
			"  --ip ADDRESS             Server IP SAN; may be repeated\n",
	)
}

func errorsNewCertificateUsage() error {
	return fmt.Errorf(
		"usage: portwayd cert generate [--output-dir DIR] " +
			"[--server-name NAME]... [--ip ADDRESS]...",
	)
}

type stringValues []string

func (values *stringValues) String() string {
	return fmt.Sprint([]string(*values))
}

func (values *stringValues) Set(value string) error {
	*values = append(*values, value)
	return nil
}
