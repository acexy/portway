//go:build windows && amd64

package system

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsConsoleHelper = "__vnetwork_windows_console_helper"

var windowsConsoleKernel = windows.NewLazySystemDLL("kernel32.dll")
var windowsConsoleInterruptHandler = windows.NewCallback(func(event uint32) uintptr {
	// Only the business process handles interactive shutdown; its waiters stay alive.
	if event == windows.CTRL_C_EVENT || event == windows.CTRL_BREAK_EVENT {
		return 1
	}
	return 0
})

func ignoreWindowsConsoleInterrupts() (func(), error) {
	procedure := windowsConsoleKernel.NewProc("SetConsoleCtrlHandler")
	if result, _, err := procedure.Call(windowsConsoleInterruptHandler, 1); result == 0 {
		return nil, fmt.Errorf("protect Windows console waiter: %w", err)
	}
	return func() { procedure.Call(windowsConsoleInterruptHandler, 0) }, nil
}

func windowsConsoleArguments(arguments []string) ([]string, error) {
	var processID uint32
	count, _, _ := windowsConsoleKernel.NewProc("GetConsoleProcessList").Call(uintptr(unsafe.Pointer(&processID)), 1)
	console := "0"
	if count != 0 {
		console = "1"
	}
	result := []string{windowsConsoleHelper, strconv.Itoa(os.Getpid()), console}
	for _, file := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		var mode uint32
		if windows.GetConsoleMode(windows.Handle(file.Fd()), &mode) == nil {
			// Console handles cannot be duplicated across processes. Reopen after attaching.
			result = append(result, "0")
			continue
		}
		if _, err := file.Stat(); err != nil {
			return nil, fmt.Errorf("inspect Windows standard stream: %w", err)
		}
		result = append(result, strconv.FormatUint(uint64(file.Fd()), 10))
	}
	return append(result, arguments...), nil
}

func parseWindowsConsoleArguments(arguments []string) (uint32, bool, [3]windows.Handle, []string, error) {
	var handles [3]windows.Handle
	invalid := errors.New("invalid Windows console helper invocation")
	if len(arguments) < 6 || (arguments[1] != "0" && arguments[1] != "1") {
		return 0, false, handles, nil, invalid
	}
	processID, err := strconv.ParseUint(arguments[0], 10, 32)
	if err != nil || processID == 0 || processID == uint64(os.Getpid()) {
		return 0, false, handles, nil, invalid
	}
	for index := range handles {
		value, err := strconv.ParseUint(arguments[index+2], 10, 64)
		if err != nil || value == uint64(windows.InvalidHandle) || (value == 0 && arguments[1] == "0") {
			return 0, false, handles, nil, invalid
		}
		handles[index] = windows.Handle(value)
	}
	if arguments[5] == windowsConsoleHelper {
		return 0, false, handles, nil, invalid
	}
	return uint32(processID), arguments[1] == "1", handles, arguments[5:], nil
}

func runWindowsConsoleCommand(arguments []string) (exitCode int, resultError error) {
	processID, attach, handles, commandArguments, err := parseWindowsConsoleArguments(arguments)
	if err != nil {
		return 0, err
	}
	executable, err := os.Executable()
	if err != nil {
		return 0, err
	}
	parent, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, processID)
	if err != nil {
		return 0, fmt.Errorf("open Windows console owner: %w", err)
	}
	defer windows.CloseHandle(parent)
	var path [32768]uint16
	length := uint32(len(path))
	if err := windows.QueryFullProcessImageName(parent, 0, &path[0], &length); err != nil {
		return 0, fmt.Errorf("identify Windows console owner: %w", err)
	}
	if !strings.EqualFold(windows.UTF16ToString(path[:length]), executable) {
		return 0, errors.New("Windows console owner is not the current executable")
	}
	var streams [3]*os.File
	defer func() {
		if resultError != nil && streams[2] != nil {
			fmt.Fprintln(streams[2], resultError)
		}
		for _, stream := range streams {
			if stream != nil {
				stream.Close()
			}
		}
	}()
	for index, handle := range handles {
		if handle == 0 {
			continue
		}
		var duplicate windows.Handle
		if err := windows.DuplicateHandle(parent, handle, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return 0, fmt.Errorf("duplicate Windows standard stream %d: %w", index, err)
		}
		streams[index] = os.NewFile(uintptr(duplicate), "redirected standard stream")
	}
	if attach {
		// A fresh Go process must start after AttachConsole resets the runtime's handlers.
		if result, _, err := windowsConsoleKernel.NewProc("FreeConsole").Call(); result == 0 {
			return 0, fmt.Errorf("detach Windows bootstrap console: %w", err)
		}
		if result, _, err := windowsConsoleKernel.NewProc("AttachConsole").Call(uintptr(processID)); result == 0 {
			return 0, fmt.Errorf("attach original Windows console: %w", err)
		}
	}
	for index := range streams {
		if streams[index] != nil {
			continue
		}
		// Console mode queries require read access even for output handles.
		name := "CONOUT$"
		if index == 0 {
			name = "CONIN$"
		}
		streams[index], err = os.OpenFile(name, os.O_RDWR, 0)
		if err != nil {
			return 0, fmt.Errorf("open Windows console stream %d: %w", index, err)
		}
	}
	stop, err := ignoreWindowsConsoleInterrupts()
	if err != nil {
		return 0, err
	}
	defer stop()
	command := exec.Command(executable, commandArguments...)
	command.Stdin, command.Stdout, command.Stderr = streams[0], streams[1], streams[2]
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return exitError.ExitCode(), nil
		}
		return 0, fmt.Errorf("start elevated Windows command: %w", err)
	}
	return 0, nil
}
