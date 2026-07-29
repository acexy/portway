// Package cli provides the shared command-line interface for Portway binaries.
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/acexy/portway/internal/buildinfo"
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
		command, found := application.command(arguments[1])
		if !found {
			application.writeUnknownCommand(stderr, arguments[1])
			return 2
		}
		application.WriteCommandHelp(stdout, command)
		return 0
	case "version", "-v", "--version":
		application.WriteVersion(stdout)
		return 0
	}

	command, found := application.command(arguments[0])
	if !found {
		application.writeUnknownCommand(stderr, arguments[0])
		return 2
	}
	if len(arguments) > 1 &&
		(arguments[1] == "-h" || arguments[1] == "--help") {
		application.WriteCommandHelp(stdout, command)
		return 0
	}
	return command.Execute(arguments[1:], stdout, stderr)
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
		_, _ = fmt.Fprintf(
			writer,
			"  %s%-12s%s %s\n",
			renderer.theme.Command,
			command.Name,
			renderer.theme.Reset,
			command.Summary,
		)
	}
	_, _ = fmt.Fprintf(
		writer,
		"  %s%-12s%s %s\n",
		renderer.theme.Command,
		"version",
		renderer.theme.Reset,
		"Show version and build information",
	)
	_, _ = fmt.Fprintf(
		writer,
		"\nRun '%s help <command>' for command details.\n",
		application.Name,
	)
}

// WriteCommandHelp renders help for one command.
func (application Application) WriteCommandHelp(writer io.Writer, command Command) {
	renderer := application.renderer(writer)
	_, _ = fmt.Fprintf(
		writer,
		"%s%s %s%s\n%s%s%s\n\n",
		renderer.theme.Accent,
		application.Name,
		command.Name,
		renderer.theme.Reset,
		renderer.theme.Muted,
		command.Summary,
		renderer.theme.Reset,
	)
	usage := command.Usage
	if usage == "" {
		usage = command.Name
	}
	_, _ = fmt.Fprintf(writer, "Usage:\n  %s %s\n", application.Name, usage)
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

// WriteVersion renders operator-friendly build metadata.
func (application Application) WriteVersion(writer io.Writer) {
	renderer := application.renderer(writer)
	_, _ = fmt.Fprintf(
		writer,
		"%s%s%s %s\n",
		renderer.theme.Accent,
		application.Name,
		renderer.theme.Reset,
		application.Version.Version,
	)
	if commit := application.Version.ShortCommit(); commit != "" {
		if application.Version.Modified {
			commit += " (modified)"
		}
		_, _ = fmt.Fprintf(writer, "Commit: %s\n", commit)
	}
	if application.Version.BuildTime != "" {
		_, _ = fmt.Fprintf(writer, "Built:  %s\n", application.Version.BuildTime)
	}
	_, _ = fmt.Fprintf(writer, "Go:     %s\n", application.Version.GoVersion)
}

func (application Application) command(name string) (Command, bool) {
	for _, command := range application.Commands {
		if command.Name == name {
			return command, true
		}
	}
	return Command{}, false
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
