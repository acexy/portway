//go:build windows && amd64

package vnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsWintunRingCapacity = 4 << 20

var windowsAdapterGUID = windows.GUID{
	Data1: 0x9f91ac7b,
	Data2: 0x9e6f,
	Data3: 0x4d26,
	Data4: [8]byte{0xa4, 0xc5, 0x70, 0x2f, 0xa8, 0x92, 0x97, 0x52},
}

type windowsWintunAPI struct {
	dll                  *windows.DLL
	createAdapter        *windows.Proc
	closeAdapter         *windows.Proc
	startSession         *windows.Proc
	endSession           *windows.Proc
	getReadWaitEvent     *windows.Proc
	receivePacket        *windows.Proc
	releaseReceivePacket *windows.Proc
	allocateSendPacket   *windows.Proc
	sendPacket           *windows.Proc
}

type windowsDevice struct {
	api         *windowsWintunAPI
	adapter     uintptr
	session     uintptr
	networkLock windows.Handle
	readEvent   windows.Handle
	closeEvent  windows.Handle
	closed      atomic.Bool
	operations  sync.RWMutex
	writeMutex  sync.Mutex
	closeOnce   sync.Once
	closeError  error
}

func openDevice() (Device, error) {
	return nil, errors.New("Windows VNet device is created during network preparation")
}

func createWindowsDevice() (*windowsDevice, error) {
	dllPath, err := windowsWintunPath()
	if err != nil {
		return nil, err
	}
	return createWindowsDeviceFrom(dllPath)
}

func createWindowsDeviceFrom(dllPath string) (*windowsDevice, error) {
	networkLock, inUse, err := acquireWindowsNetworkLock()
	if err != nil {
		return nil, err
	}
	if inUse {
		_ = windows.CloseHandle(networkLock)
		return nil, errors.New("Windows VNet network is in use")
	}
	releaseNetworkLock := true
	defer func() {
		if releaseNetworkLock {
			_ = windows.ReleaseMutex(networkLock)
			_ = windows.CloseHandle(networkLock)
		}
	}()
	device, err := createWindowsDeviceWithLock(dllPath, networkLock)
	if err != nil {
		return nil, err
	}
	releaseNetworkLock = false
	return device, nil
}

func createWindowsDeviceWithLock(dllPath string, networkLock windows.Handle) (*windowsDevice, error) {
	api, err := loadWindowsWintun(dllPath)
	if err != nil {
		return nil, err
	}
	name, _ := windows.UTF16PtrFromString(LogicalInterfaceName)
	tunnelType, _ := windows.UTF16PtrFromString("Portway")
	adapter, _, callError := api.createAdapter.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(tunnelType)),
		uintptr(unsafe.Pointer(&windowsAdapterGUID)),
	)
	if adapter == 0 {
		api.dll.Release()
		return nil, fmt.Errorf("create Windows Wintun adapter: %w", normalizeWindowsCallError(callError))
	}
	session, _, callError := api.startSession.Call(adapter, windowsWintunRingCapacity)
	if session == 0 {
		api.closeAdapter.Call(adapter)
		api.dll.Release()
		return nil, fmt.Errorf("start Windows Wintun session: %w", normalizeWindowsCallError(callError))
	}
	readEvent, _, callError := api.getReadWaitEvent.Call(session)
	if readEvent == 0 {
		api.endSession.Call(session)
		api.closeAdapter.Call(adapter)
		api.dll.Release()
		return nil, fmt.Errorf("get Windows Wintun read event: %w", normalizeWindowsCallError(callError))
	}
	closeEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		api.endSession.Call(session)
		api.closeAdapter.Call(adapter)
		api.dll.Release()
		return nil, fmt.Errorf("create Windows VNet close event: %w", err)
	}
	return &windowsDevice{
		api:         api,
		adapter:     adapter,
		session:     session,
		networkLock: networkLock,
		readEvent:   windows.Handle(readEvent),
		closeEvent:  closeEvent,
	}, nil
}

func (device *windowsDevice) MigrateNetwork(ctx context.Context, previous, next NetworkSpec) error {
	return migrateWindowsNetwork(ctx, previous, next)
}

func windowsWintunPath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve Windows executable path: %w", err)
	}
	return filepath.Join(filepath.Dir(executable), "wintun.dll"), nil
}

func loadWindowsWintun(dllPath string) (*windowsWintunAPI, error) {
	// VNet loads only the release-bundled library beside the executable. An
	// absolute path prevents the working directory and PATH from selecting it.
	if !filepath.IsAbs(dllPath) {
		return nil, errors.New("Windows Wintun library path is not absolute")
	}
	info, err := os.Lstat(dllPath)
	if err != nil {
		return nil, fmt.Errorf("locate Windows Wintun library beside the executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("Windows Wintun library is not a regular file")
	}
	dll, err := windows.LoadDLL(dllPath)
	if err != nil {
		return nil, fmt.Errorf("load Windows Wintun library: %w", err)
	}
	api := &windowsWintunAPI{dll: dll}
	procedures := []struct {
		name   string
		target **windows.Proc
	}{
		{"WintunCreateAdapter", &api.createAdapter},
		{"WintunCloseAdapter", &api.closeAdapter},
		{"WintunStartSession", &api.startSession},
		{"WintunEndSession", &api.endSession},
		{"WintunGetReadWaitEvent", &api.getReadWaitEvent},
		{"WintunReceivePacket", &api.receivePacket},
		{"WintunReleaseReceivePacket", &api.releaseReceivePacket},
		{"WintunAllocateSendPacket", &api.allocateSendPacket},
		{"WintunSendPacket", &api.sendPacket},
	}
	for _, procedure := range procedures {
		resolved, resolveError := dll.FindProc(procedure.name)
		if resolveError != nil {
			dll.Release()
			return nil, fmt.Errorf("resolve Windows Wintun procedure %s: %w", procedure.name, resolveError)
		}
		*procedure.target = resolved
	}
	return api, nil
}

func (device *windowsDevice) Name() string { return LogicalInterfaceName }

func (device *windowsDevice) ReadPacket(packet []byte) (int, error) {
	device.operations.RLock()
	defer device.operations.RUnlock()
	for {
		if device.closed.Load() {
			return 0, os.ErrClosed
		}
		var size uint32
		pointer, _, callError := device.api.receivePacket.Call(
			device.session,
			uintptr(unsafe.Pointer(&size)),
		)
		if pointer != 0 {
			if uint64(size) > uint64(len(packet)) {
				device.api.releaseReceivePacket.Call(device.session, pointer)
				return 0, io.ErrShortBuffer
			}
			// Wintun owns the receive ring. Copy before releasing its packet slot.
			copy(packet, unsafe.Slice((*byte)(unsafe.Pointer(pointer)), int(size)))
			device.api.releaseReceivePacket.Call(device.session, pointer)
			return int(size), nil
		}
		callError = normalizeWindowsCallError(callError)
		if !errors.Is(callError, windows.ERROR_NO_MORE_ITEMS) {
			if errors.Is(callError, windows.ERROR_HANDLE_EOF) || device.closed.Load() {
				return 0, os.ErrClosed
			}
			return 0, fmt.Errorf("receive Windows Wintun packet: %w", callError)
		}
		waitResult, err := windows.WaitForMultipleObjects(
			[]windows.Handle{device.readEvent, device.closeEvent},
			false,
			windows.INFINITE,
		)
		if err != nil {
			return 0, fmt.Errorf("wait for Windows Wintun packet: %w", err)
		}
		if waitResult == windows.WAIT_OBJECT_0+1 {
			return 0, os.ErrClosed
		}
		if waitResult != windows.WAIT_OBJECT_0 {
			return 0, fmt.Errorf("wait for Windows Wintun packet: unexpected result %d", waitResult)
		}
	}
}

func (device *windowsDevice) WritePacket(packet []byte) (int, error) {
	if len(packet) == 0 || len(packet) > 0xffff {
		return 0, ErrInvalidPacket
	}
	device.operations.RLock()
	defer device.operations.RUnlock()
	if device.closed.Load() {
		return 0, os.ErrClosed
	}
	device.writeMutex.Lock()
	defer device.writeMutex.Unlock()
	pointer, _, callError := device.api.allocateSendPacket.Call(device.session, uintptr(len(packet)))
	if pointer == 0 {
		callError = normalizeWindowsCallError(callError)
		if errors.Is(callError, windows.ERROR_HANDLE_EOF) || device.closed.Load() {
			return 0, os.ErrClosed
		}
		return 0, fmt.Errorf("allocate Windows Wintun packet: %w", callError)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(pointer)), len(packet)), packet)
	device.api.sendPacket.Call(device.session, pointer)
	return len(packet), nil
}

func (device *windowsDevice) Close() error {
	device.closeOnce.Do(func() {
		device.closed.Store(true)
		// Wake a receive waiter before taking the exclusive operation lock.
		// Releasing the DLL is safe only after every active API call returns.
		if err := windows.SetEvent(device.closeEvent); err != nil {
			device.closeError = err
		}
		device.operations.Lock()
		device.api.endSession.Call(device.session)
		device.api.closeAdapter.Call(device.adapter)
		if err := windows.CloseHandle(device.closeEvent); device.closeError == nil {
			device.closeError = err
		}
		if err := device.api.dll.Release(); device.closeError == nil {
			device.closeError = err
		}
		if err := windows.ReleaseMutex(device.networkLock); device.closeError == nil {
			device.closeError = err
		}
		if err := windows.CloseHandle(device.networkLock); device.closeError == nil {
			device.closeError = err
		}
		device.operations.Unlock()
	})
	return device.closeError
}

func normalizeWindowsCallError(err error) error {
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return syscall.EINVAL
	}
	if err == nil {
		return syscall.EINVAL
	}
	return err
}
