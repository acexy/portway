// Package cli provides the shared command-line interface for Portway binaries.
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/acexy/portway/internal/buildinfo"
	"github.com/acexy/portway/internal/compression"
	"github.com/acexy/portway/internal/protocol"
)

// ColorMode controls ANSI styling.
type ColorMode uint8

const (
	// ColorAuto enables colors only for an interactive terminal.
	ColorAuto ColorMode = iota
	// ColorAlways always enables colors.
	ColorAlways
	// ColorNever disables colors.
	ColorNever
)

// Theme contains replaceable ANSI styles used by the CLI renderer.
type Theme struct {
	Accent  string
	Command string
	Muted   string
	Error   string
	Reset   string
}

// DefaultTheme returns the shared Portway terminal theme.
func DefaultTheme() Theme {
	return Theme{
		Accent:  "\x1b[1;36m",
		Command: "\x1b[1;33m",
		Muted:   "\x1b[2m",
		Error:   "\x1b[1;31m",
		Reset:   "\x1b[0m",
	}
}

// Option documents one command option.
type Option struct {
	Usage       string
	Description string
}

// Command describes one top-level application command.
type Command struct {
	Name        string
	Usage       string
	Summary     string
	Options     []Option
	Subcommands []Command
	Execute     func(arguments []string, stdout io.Writer, stderr io.Writer) int
}

// Application describes a Portway command-line program.
type Application struct {
	Name        string
	Title       string
	Description string
	Version     buildinfo.Info
	Commands    []Command
	Theme       Theme
	Color       ColorMode
}

// Run dispatches one command and renders consistent help and errors.
func (application Application) Run(
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	if len(arguments) == 0 {
		application.WriteHelp(stdout)
		return 0
	}
	switch arguments[0] {
	case "help", "-h", "--help":
		if len(arguments) == 1 {
			application.WriteHelp(stdout)
			return 0
		}
		return application.writeCommandPathHelp(arguments[1:], stdout, stderr)
	case "version", "-v", "--version":
		application.WriteVersion(stdout)
		return 0
	}

	command, path, remaining, found := application.resolveCommand(arguments)
	if !found {
		application.writeUnknownCommand(stderr, strings.Join(path, " "))
		return 2
	}
	if len(remaining) == 0 && len(command.Subcommands) > 0 {
		application.writeCommandHelp(stdout, strings.Join(path, " "), command)
		return 0
	}
	if len(remaining) > 0 &&
		(remaining[0] == "-h" || remaining[0] == "--help") {
		application.writeCommandHelp(stdout, strings.Join(path, " "), command)
		return 0
	}
	if command.Execute == nil {
		application.writeCommandHelp(stdout, strings.Join(path, " "), command)
		return 0
	}
	return command.Execute(remaining, stdout, stderr)
}

// WriteHelp renders the application overview.
func (application Application) WriteHelp(writer io.Writer) {
	renderer := application.renderer(writer)
	_, _ = fmt.Fprintf(
		writer,
		"%s%s%s\n%s%s%s\n\n",
		renderer.theme.Accent,
		application.Title,
		renderer.theme.Reset,
		renderer.theme.Muted,
		application.Description,
		renderer.theme.Reset,
	)
	_, _ = fmt.Fprintf(
		writer,
		"%sVersion:%s %s\n\n",
		renderer.theme.Muted,
		renderer.theme.Reset,
		application.Version.Version,
	)
	_, _ = fmt.Fprintf(writer, "Usage:\n  %s <command> [options]\n\n", application.Name)
	_, _ = fmt.Fprintln(writer, "Commands:")
	for _, command := range application.Commands {
		application.writeCommandList(writer, renderer, command, nil, "  ")
	}
	_, _ = fmt.Fprintf(
		writer,
		"  %s%-12s%s %s\n",
		renderer.theme.Command,
		"version",
		renderer.theme.Reset,
		"Show version",
	)
	_, _ = fmt.Fprintf(
		writer,
		"\nRun '%s help <command>' for command details.\n",
		application.Name,
	)
}

// WriteCommandHelp renders help for one command.
func (application Application) WriteCommandHelp(writer io.Writer, command Command) {
	application.writeCommandHelp(writer, command.Name, command)
}

func (application Application) writeCommandHelp(
	writer io.Writer,
	path string,
	command Command,
) {
	renderer := application.renderer(writer)
	_, _ = fmt.Fprintf(
		writer,
		"%s%s %s%s\n%s%s%s\n\n",
		renderer.theme.Accent,
		application.Name,
		path,
		renderer.theme.Reset,
		renderer.theme.Muted,
		command.Summary,
		renderer.theme.Reset,
	)
	usage := command.Usage
	if usage == "" {
		usage = path
	} else if !strings.HasPrefix(usage, path) {
		parent := ""
		if separator := strings.LastIndexByte(path, ' '); separator >= 0 {
			parent = path[:separator+1]
		}
		usage = parent + usage
	}
	_, _ = fmt.Fprintf(writer, "Usage:\n  %s %s\n", application.Name, usage)
	if len(command.Subcommands) > 0 {
		_, _ = fmt.Fprintln(writer, "\nSubcommands:")
		for _, subcommand := range command.Subcommands {
			application.writeCommandList(
				writer,
				renderer,
				subcommand,
				strings.Fields(path),
				"  ",
			)
		}
	}
	if len(command.Options) == 0 {
		return
	}
	_, _ = fmt.Fprintln(writer, "\nOptions:")
	for _, option := range command.Options {
		_, _ = fmt.Fprintf(
			writer,
			"  %s%-24s%s %s\n",
			renderer.theme.Command,
			option.Usage,
			renderer.theme.Reset,
			option.Description,
		)
	}
}

// WriteVersion renders the application and core protocol versions.
func (application Application) WriteVersion(writer io.Writer) {
	_, _ = fmt.Fprintf(writer, "version: %s\n", application.Version.Version)
	_, _ = fmt.Fprintf(writer, "core-protocol: %d\n", protocol.CoreVersion)
	algorithms := compression.SupportedAlgorithms()
	values := make([]string, 0, len(algorithms))
	for _, algorithm := range algorithms {
		values = append(values, string(algorithm))
	}
	_, _ = fmt.Fprintf(writer, "compression-protocols: %s\n", strings.Join(values, ","))
}

func (application Application) resolveCommand(
	arguments []string,
) (Command, []string, []string, bool) {
	commands := application.Commands
	path := make([]string, 0, len(arguments))
	for index, argument := range arguments {
		command, found := findCommand(commands, argument)
		path = append(path, argument)
		if !found {
			return Command{}, path, nil, false
		}
		if len(command.Subcommands) == 0 {
			return command, path, arguments[index+1:], true
		}
		if index == len(arguments)-1 {
			return command, path, nil, true
		}
		if arguments[index+1] == "-h" || arguments[index+1] == "--help" {
			return command, path, arguments[index+1:], true
		}
		commands = command.Subcommands
	}
	return Command{}, path, nil, false
}

func findCommand(commands []Command, name string) (Command, bool) {
	for _, command := range commands {
		if command.Name == name {
			return command, true
		}
	}
	return Command{}, false
}

func (application Application) writeCommandPathHelp(
	path []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	command, resolvedPath, remaining, found := application.resolveCommand(path)
	if !found || len(remaining) != 0 {
		application.writeUnknownCommand(stderr, strings.Join(resolvedPath, " "))
		return 2
	}
	application.writeCommandHelp(stdout, strings.Join(resolvedPath, " "), command)
	return 0
}

func (application Application) writeCommandList(
	writer io.Writer,
	renderer renderer,
	command Command,
	parent []string,
	indent string,
) {
	path := append(append([]string(nil), parent...), command.Name)
	display := strings.Join(path, " ")
	if command.Usage != "" {
		usageWords := strings.Fields(command.Usage)
		if len(usageWords) > 1 {
			display += " " + strings.Join(usageWords[1:], " ")
		}
	}
	_, _ = fmt.Fprintf(
		writer,
		"%s%s%-20s%s %s\n",
		indent,
		renderer.theme.Command,
		display,
		renderer.theme.Reset,
		command.Summary,
	)
	for _, subcommand := range command.Subcommands {
		application.writeCommandList(writer, renderer, subcommand, path, indent+"  ")
	}
}

func (application Application) writeUnknownCommand(writer io.Writer, name string) {
	renderer := application.renderer(writer)
	_, _ = fmt.Fprintf(
		writer,
		"%sError:%s unknown command %q\n\n",
		renderer.theme.Error,
		renderer.theme.Reset,
		name,
	)
	application.WriteHelp(writer)
}

type renderer struct {
	theme Theme
}

func (application Application) renderer(writer io.Writer) renderer {
	theme := application.Theme
	if theme == (Theme{}) {
		theme = DefaultTheme()
	}
	if !colorEnabled(writer, application.Color) {
		theme = Theme{}
	}
	return renderer{theme: theme}
}

func colorEnabled(writer io.Writer, mode ColorMode) bool {
	switch mode {
	case ColorAlways:
		return true
	case ColorNever:
		return false
	}
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled {
		return false
	}
	if strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	file, isFile := writer.(*os.File)
	if !isFile {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
