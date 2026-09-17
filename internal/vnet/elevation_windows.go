//go:build windows && amd64

package vnet

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsSeeMaskNoCloseProcess = 0x00000040
	windowsShowNormal            = 1
	windowsElevationTimeout      = 2 * time.Minute
	windowsUninstallHelper       = "__vnetwork_windows_uninstall_helper"
	windowsHelperResponseLimit   = 64 * 1024
)

var windowsShellExecuteEx = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

type windowsShellExecuteInfo struct {
	size       uint32
	mask       uint32
	window     windows.Handle
	verb       *uint16
	file       *uint16
	parameters *uint16
	directory  *uint16
	show       int32
	instance   windows.Handle
	idList     unsafe.Pointer
	class      *uint16
	classKey   windows.Handle
	hotKey     uint32
	icon       windows.Handle
	process    windows.Handle
}

type windowsUninstallResponse struct {
	Nonce  string `json:"nonce"`
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

// ElevateCurrentProcess restarts the current command through UAC and waits for
// the elevated process. Callers must return the child exit code when relaunched.
func ElevateCurrentProcess() (exitCode int, relaunched bool, err error) {
	if windowsProcessElevated() {
		return 0, false, nil
	}
	return elevateWindowsProcess(os.Args[1:])
}

func elevateWindowsProcess(arguments []string) (exitCode int, relaunched bool, err error) {
	executable, err := os.Executable()
	if err != nil {
		return 0, false, fmt.Errorf("resolve current executable for Windows elevation: %w", err)
	}
	directory, err := os.Getwd()
	if err != nil {
		return 0, false, fmt.Errorf("resolve current directory for Windows elevation: %w", err)
	}
	verbPointer, _ := windows.UTF16PtrFromString("runas")
	executablePointer, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return 0, false, err
	}
	parametersPointer, err := windows.UTF16PtrFromString(windowsCommandLine(arguments))
	if err != nil {
		return 0, false, err
	}
	directoryPointer, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return 0, false, err
	}
	info := windowsShellExecuteInfo{
		mask: windowsSeeMaskNoCloseProcess, verb: verbPointer, file: executablePointer,
		parameters: parametersPointer, directory: directoryPointer, show: windowsShowNormal,
	}
	info.size = uint32(unsafe.Sizeof(info))
	success, _, callError := windowsShellExecuteEx.Call(uintptr(unsafe.Pointer(&info)))
	if success == 0 {
		if errors.Is(callError, windows.ERROR_CANCELLED) {
			return 0, false, errors.New("administrator authorization was canceled")
		}
		return 0, false, fmt.Errorf("request Windows administrator authorization: %w", callError)
	}
	if info.process == 0 {
		return 0, false, errors.New("Windows elevation did not return a process handle")
	}
	defer windows.CloseHandle(info.process)
	if _, err := windows.WaitForSingleObject(info.process, windows.INFINITE); err != nil {
		return 0, false, fmt.Errorf("wait for elevated Windows process: %w", err)
	}
	var childExitCode uint32
	if err := windows.GetExitCodeProcess(info.process, &childExitCode); err != nil {
		return 0, false, fmt.Errorf("read elevated Windows process exit code: %w", err)
	}
	return int(childExitCode), true, nil
}

func uninstallNetworkAuthorized() (string, error) {
	if windowsProcessElevated() {
		return UninstallNetwork()
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "PermissionDenied", fmt.Errorf("create Windows elevation response channel: %w", err)
	}
	defer listener.Close()
	if deadlineListener, ok := listener.(*net.TCPListener); ok {
		_ = deadlineListener.SetDeadline(time.Now().Add(windowsElevationTimeout))
	}
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "PermissionDenied", fmt.Errorf("create Windows elevation nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	exitCode, _, err := elevateWindowsProcess([]string{windowsUninstallHelper, listener.Addr().String(), nonce})
	if err != nil {
		return "PermissionDenied", err
	}
	connection, err := listener.Accept()
	if err != nil {
		return "PermissionDenied", fmt.Errorf("receive elevated Windows uninstall result: %w", err)
	}
	defer connection.Close()
	return readWindowsUninstallResponse(connection, nonce, exitCode)
}

func readWindowsUninstallResponse(reader io.Reader, nonce string, exitCode int) (string, error) {
	var response windowsUninstallResponse
	decoder := json.NewDecoder(io.LimitReader(reader, windowsHelperResponseLimit))
	if err := decoder.Decode(&response); err != nil {
		return "PermissionDenied", fmt.Errorf("decode elevated Windows uninstall result: %w", err)
	}
	if response.Nonce != nonce {
		return "PermissionDenied", errors.New("elevated Windows uninstall response authentication failed")
	}
	if exitCode != 0 {
		return "PermissionDenied", fmt.Errorf("elevated Windows uninstall helper exited with code %d", exitCode)
	}
	if response.Error != "" {
		return response.Result, errors.New(response.Error)
	}
	return response.Result, nil
}

func runWindowsElevationHelper(arguments []string) (bool, error) {
	if len(arguments) == 0 || arguments[0] != windowsUninstallHelper {
		return false, nil
	}
	if len(arguments) != 3 || !windowsProcessElevated() {
		return true, errors.New("invalid Windows VNet uninstall helper invocation")
	}
	address, nonce := arguments[1], arguments[2]
	if len(nonce) != 64 {
		return true, errors.New("invalid Windows VNet uninstall helper nonce")
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return true, errors.New("invalid Windows VNet uninstall helper nonce")
	}
	tcpAddress, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil || !tcpAddress.IP.IsLoopback() {
		return true, errors.New("invalid Windows VNet uninstall helper address")
	}
	connection, err := net.DialTimeout("tcp4", address, windowsElevationTimeout)
	if err != nil {
		return true, fmt.Errorf("connect Windows elevation response channel: %w", err)
	}
	defer connection.Close()
	result, uninstallError := UninstallNetwork()
	response := windowsUninstallResponse{Nonce: nonce, Result: result}
	if uninstallError != nil {
		response.Error = uninstallError.Error()
	}
	if err := json.NewEncoder(connection).Encode(response); err != nil {
		return true, fmt.Errorf("send Windows VNet uninstall result: %w", err)
	}
	return true, nil
}

func windowsCommandLine(arguments []string) string {
	escaped := make([]string, len(arguments))
	for index, argument := range arguments {
		escaped[index] = syscall.EscapeArg(argument)
	}
	return strings.Join(escaped, " ")
}
