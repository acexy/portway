//go:build windows && amd64

package vnet

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsConsoleTestCommand = "--portway-console-test"

func TestMain(tests *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == windowsConsoleHelper {
		if _, err := runWindowsElevationHelper(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if len(os.Args) > 2 && os.Args[1] == windowsConsoleTestCommand {
		code, err := runWindowsConsoleTestProcess(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(code)
	}
	os.Exit(tests.Run())
}

func runWindowsConsoleTestProcess(arguments []string) (int, error) {
	switch arguments[0] {
	case "bootstrap":
		return runWindowsConsoleCommand(arguments[1:])
	case "owner":
		stop, err := ignoreWindowsConsoleInterrupts()
		if err != nil {
			return 0, err
		}
		defer stop()
		if arguments[1] == "console-stdio" {
			os.Stdin, err = os.OpenFile("CONIN$", os.O_RDWR, 0)
			if err != nil {
				return 0, err
			}
			os.Stdout, err = os.OpenFile("CONOUT$", os.O_RDWR, 0)
			if err != nil {
				return 0, err
			}
		}
		commandArguments := []string{windowsConsoleTestCommand, "worker", strconv.Itoa(os.Getpid()), arguments[1]}
		bootstrapArguments, err := windowsConsoleArguments(commandArguments)
		if err != nil {
			return 0, err
		}
		if arguments[2] == "uac" {
			code, _, err := elevateWindowsProcess(bootstrapArguments)
			return code, err
		}
		command := exec.Command(os.Args[0], append([]string{windowsConsoleTestCommand, "bootstrap"}, bootstrapArguments[1:]...)...)
		command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE, HideWindow: true}
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := command.Run(); err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				return exitError.ExitCode(), nil
			}
			return 0, err
		}
		return 0, nil
	case "worker":
		var input []byte
		if arguments[2] == "console-stdio" {
			for _, stream := range []*os.File{os.Stdin, os.Stdout} {
				var mode uint32
				if err := windows.GetConsoleMode(windows.Handle(stream.Fd()), &mode); err != nil {
					return 0, fmt.Errorf("standard console handle lost: %w", err)
				}
			}
			fmt.Fprintln(os.Stderr, "console-stdio:preserved")
		} else {
			var err error
			input, err = io.ReadAll(os.Stdin)
			if err != nil {
				return 0, err
			}
		}
		fmt.Fprintf(os.Stdout, "stdout:%s", input)
		fmt.Fprintln(os.Stderr, "stderr:preserved")
		if strings.HasPrefix(arguments[2], "console") {
			var processIDs [16]uint32
			count, _, callError := windowsConsoleKernel.NewProc("GetConsoleProcessList").Call(uintptr(unsafe.Pointer(&processIDs[0])), uintptr(len(processIDs)))
			if count == 0 || count > uintptr(len(processIDs)) {
				return 0, fmt.Errorf("read console members: %v", callError)
			}
			owner, _ := strconv.ParseUint(arguments[1], 10, 32)
			found := false
			for _, processID := range processIDs[:count] {
				found = found || processID == uint32(owner)
			}
			if !found {
				return 0, fmt.Errorf("worker did not attach to the owner's console")
			}
			interrupts := make(chan os.Signal, 1)
			signal.Notify(interrupts, os.Interrupt)
			defer signal.Stop(interrupts)
			// The owner has an isolated hidden console, so this cannot signal the test runner.
			for _, event := range []uint32{windows.CTRL_C_EVENT, windows.CTRL_BREAK_EVENT} {
				if err := windows.GenerateConsoleCtrlEvent(event, 0); err != nil {
					return 0, err
				}
				select {
				case <-interrupts:
				case <-time.After(5 * time.Second):
					return 0, fmt.Errorf("Go interrupt handler did not receive console event %d", event)
				}
			}
			fmt.Fprintln(os.Stderr, "console:shared;interrupt:received")
		}
		fmt.Fprintf(os.Stderr, "elevated:%t\n", windowsProcessElevated())
		return 23, nil
	}
	return 0, fmt.Errorf("unknown console test process")
}

func TestWindowsConsoleHandoff(t *testing.T) {
	for _, mode := range []string{"redirected", "console", "console-stdio"} {
		t.Run(mode, func(t *testing.T) {
			verifyWindowsConsoleHandoff(t, mode, false)
		})
	}
}

func TestWindowsConsoleElevationLive(t *testing.T) {
	if os.Getenv("PORTWAY_TEST_WINDOWS_ELEVATION") != "1" {
		t.Skip("set PORTWAY_TEST_WINDOWS_ELEVATION=1 to approve an actual UAC console handoff")
	}
	for _, mode := range []string{"console", "console-stdio"} {
		t.Run(mode, func(t *testing.T) {
			verifyWindowsConsoleHandoff(t, mode, true)
		})
	}
}

func verifyWindowsConsoleHandoff(t *testing.T, mode string, elevate bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	elevation := "local"
	flags := uint32(0x00000008) // DETACHED_PROCESS also exercises callers without a console.
	if strings.HasPrefix(mode, "console") {
		flags = windows.CREATE_NEW_CONSOLE
	}
	if elevate {
		elevation = "uac"
	}
	command := exec.CommandContext(ctx, os.Args[0], windowsConsoleTestCommand, "owner", mode, elevation)
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags, HideWindow: true}
	command.WaitDelay = 5 * time.Second
	command.Stdin = strings.NewReader("input preserved\n")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if exitError, ok := err.(*exec.ExitError); !ok || exitError.ExitCode() != 23 {
		t.Fatalf("handoff exit = %v; stdout=%q; stderr=%q", err, stdout.String(), stderr.String())
	}
	if mode == "console-stdio" && !strings.Contains(stderr.String(), "console-stdio:preserved") {
		t.Fatalf("console standard streams lost: %q", stderr.String())
	}
	if (mode != "console-stdio" && !strings.Contains(stdout.String(), "stdout:input preserved\n")) || !strings.Contains(stderr.String(), "stderr:preserved") {
		t.Fatalf("standard streams lost: stdout=%q; stderr=%q", stdout.String(), stderr.String())
	}
	if strings.HasPrefix(mode, "console") && !strings.Contains(stderr.String(), "console:shared;interrupt:received") {
		t.Fatalf("console/signal handoff failed: %q", stderr.String())
	}
	if elevate && !strings.Contains(stderr.String(), "elevated:true") {
		t.Fatalf("worker was not elevated: %q", stderr.String())
	}
}

func TestParseWindowsConsoleArguments(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"0", "1", "0", "0", "0", "run"},
		{"42", "2", "0", "0", "0", "run"},
		{"42", "0", "0", "4", "8", "run"},
		{"42", "1", "invalid", "0", "0", "run"},
		{"42", "1", "0", "0", "0", windowsConsoleHelper},
	} {
		if _, _, _, _, err := parseWindowsConsoleArguments(arguments); err == nil {
			t.Errorf("accepted invalid arguments: %q", arguments)
		}
	}
}
