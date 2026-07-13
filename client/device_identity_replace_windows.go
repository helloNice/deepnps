//go:build windows

package client

import (
	"syscall"
	"unsafe"
)

const (
	deviceMoveFileReplaceExisting = 0x1
	deviceMoveFileWriteThrough    = 0x8
)

var deviceMoveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func replaceDeviceIdentityFile(tmpPath, path string) error {
	from, err := syscall.UTF16PtrFromString(tmpPath)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	result, _, callErr := deviceMoveFileExW.Call(
		uintptr(unsafe.Pointer(from)),
		uintptr(unsafe.Pointer(to)),
		uintptr(deviceMoveFileReplaceExisting|deviceMoveFileWriteThrough),
	)
	if result == 0 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return syscall.EINVAL
	}
	return nil
}
