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
	"github.com/acexy/portway/internal/config/gen"
	"github.com/acexy/portway/internal/lifecycle"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/server"
	"github.com/acexy/portway/internal/vnet"
)

func main() {
	if handled, err := vnet.RunPlatformHelper(os.Args[1:]); handled {
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "portwayd VNet helper: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
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
				Usage:   "run [FILE]",
				Summary: "Start the Portway server",
				Execute: runServerCommand,
			},
			{
				Name:    "gen",
				Summary: "Generate server resources",
				Subcommands: []cli.Command{
					{
						Name:    "config",
						Usage:   "config [full]",
						Summary: "Generate server.yaml in the current directory",
						Options: []cli.Option{{
							Usage:       "full",
							Description: "Generate the complete annotated configuration",
						}},
						Execute: runGenerateServerConfiguration,
					},
					{
						Name:    "cert",
						Usage:   "cert [options]",
						Summary: "Generate an internal CA and server certificate",
						Options: []cli.Option{
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
						Execute: runGenerateCertificate,
					},
				},
			},
			{
				Name: "vnetwork", Summary: "Manage the Portway virtual network",
				Subcommands: []cli.Command{
					{Name: "status", Usage: "status", Summary: "Inspect the owned portway0 network", Execute: runVNetworkStatus},
					{Name: "install", Usage: "install [FILE]", Summary: "Install the configured portway0 network", Execute: runVNetworkInstall},
					{Name: "repair", Usage: "repair [FILE]", Summary: "Repair the owned portway0 network", Execute: runVNetworkRepair},
					{Name: "uninstall", Usage: "uninstall", Summary: "Safely remove the owned portway0 network", Execute: runServerVNetworkUninstall},
				},
			},
		},
	}
	return application.Run(arguments, stdout, stderr)
}

func runVNetworkStatus(arguments []string, stdout io.Writer, stderr io.Writer) int {
	if !vnet.ManualNetworkManagementSupported() {
		return reportUnsupportedVNetworkManagement(stderr)
	}
	if len(arguments) != 0 {
		_, _ = io.WriteString(stderr, "portwayd vnetwork status: no arguments are allowed\n")
		return 2
	}
	status, err := vnet.InspectNetwork()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "portwayd vnetwork status: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "installed: %t\ninterface: %s\ncidr: %s\nlocal_ip: %s\n", status.Installed, status.InterfaceName, status.CIDR, status.LocalIP)
	return 0
}

func runVNetworkInstall(arguments []string, stdout io.Writer, stderr io.Writer) int {
	return runVNetworkConfigure(arguments, stdout, stderr, false)
}

func runVNetworkRepair(arguments []string, stdout io.Writer, stderr io.Writer) int {
	return runVNetworkConfigure(arguments, stdout, stderr, true)
}

func runVNetworkConfigure(arguments []string, stdout io.Writer, stderr io.Writer, repair bool) int {
	if !vnet.ManualNetworkManagementSupported() {
		return reportUnsupportedVNetworkManagement(stderr)
	}
	path, valid := serverConfigurationPath(arguments)
	if !valid {
		_, _ = io.WriteString(stderr, "portwayd vnetwork install: at most one configuration file is allowed\n")
		return 2
	}
	configuration, err := config.LoadServer(path, false)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "portwayd vnetwork install: %v\n", err)
		return 1
	}
	if !configuration.VirtualNetwork.Enabled {
		_, _ = io.WriteString(stderr, "portwayd vnetwork install: virtual_network is disabled\n")
		return 1
	}
	spec := vnet.NetworkSpec{Role: vnet.NetworkRoleServer, CIDR: configuration.VirtualNetwork.CIDR,
		LocalIP: configuration.VirtualNetwork.ServerIP, ServerIP: configuration.VirtualNetwork.ServerIP, MTU: 1280, OwnerUID: os.Getuid()}
	var device vnet.Device
	if repair {
		device, err = vnet.RepairNetwork(spec)
	} else {
		device, err = vnet.PrepareNetwork(spec)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "portwayd vnetwork install: %v\n", err)
		return 1
	}
	_ = device.Close()
	_, _ = io.WriteString(stdout, "Installed\n")
	return 0
}

func runServerVNetworkUninstall(arguments []string, stdout io.Writer, stderr io.Writer) int {
	if !vnet.ManualNetworkManagementSupported() {
		return reportUnsupportedVNetworkManagement(stderr)
	}
	if len(arguments) != 0 {
		_, _ = io.WriteString(stderr, "portwayd vnetwork uninstall: no arguments are allowed\n")
		return 2
	}
	result, err := vnet.UninstallNetwork()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "portwayd vnetwork uninstall: %s: %v\n", result, err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, result)
	return 0
}

func reportUnsupportedVNetworkManagement(stderr io.Writer) int {
	_, _ = io.WriteString(stderr, "portwayd vnetwork: manual management is unavailable on this platform; VNet is managed automatically during run\n")
	return 1
}

func runGenerateCertificate(
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	if err := runCertificateCommand(arguments, stdout, stderr); err != nil {
		_, _ = fmt.Fprintf(stderr, "portwayd gen cert: %v\n", err)
		return 1
	}
	return 0
}

func runGenerateServerConfiguration(
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	full, err := gen.ParseMode(arguments)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "portwayd gen config: %v\n", err)
		return 2
	}
	path, err := gen.Generate(gen.TargetServer, full)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "portwayd gen config: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "Created server configuration: %s\n", path)
	return 0
}

func runServerCommand(
	arguments []string,
	_ io.Writer,
	stderr io.Writer,
) int {
	configPath, valid := serverConfigurationPath(arguments)
	if !valid {
		_, _ = io.WriteString(stderr, "portwayd run: at most one configuration file is allowed\n")
		return 2
	}

	log := logging.New("server")

	configuration, err := config.LoadServer(configPath, false)
	if err != nil {
		log.Error("failed to load server configuration", err)
		return 1
	}
	if err := logging.EnableConsole(configuration.LogLevel); err != nil {
		log.Error("failed to configure logging", err)
		return 1
	}
	log.InfoWithFields("server configuration loaded", map[string]any{
		"event":                 "configuration_loaded",
		"config_file":           configPath,
		"log_level":             configuration.LogLevel,
		"transport":             configuration.Transport.Type,
		"governed_clients_path": configuration.Authentication.GovernedClientsPath,
		"managed_clients_path":  configuration.Authentication.ManagedClientsPath,
		"governed_client_count": len(configuration.GovernedClients),
		"managed_client_count":  len(configuration.ManagedClients),
	})

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

func serverConfigurationPath(arguments []string) (string, bool) {
	switch len(arguments) {
	case 0:
		return "server.yaml", true
	case 1:
		return arguments[0], true
	default:
		return "", false
	}
}

func runCertificateCommand(
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
) error {
	flags := flag.NewFlagSet("portwayd gen cert", flag.ContinueOnError)
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
	if err := flags.Parse(arguments); err != nil {
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

type stringValues []string

func (values *stringValues) String() string {
	return fmt.Sprint([]string(*values))
}

func (values *stringValues) Set(value string) error {
	*values = append(*values, value)
	return nil
}
