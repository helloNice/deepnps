//go:build windows

package client

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type dpapiDeviceSecretProtector struct{}

func defaultDeviceSecretProtector(_ string) DeviceSecretProtector {
	return dpapiDeviceSecretProtector{}
}

func (dpapiDeviceSecretProtector) Name() string {
	return "windows-dpapi"
}

func (dpapiDeviceSecretProtector) Protect(plain []byte) ([]byte, error) {
	return dpapiCryptProtect(plain)
}

func (dpapiDeviceSecretProtector) Unprotect(ciphertext []byte) ([]byte, error) {
	return dpapiCryptUnprotect(ciphertext)
}

func dpapiCryptProtect(plain []byte) ([]byte, error) {
	in := bytesToDataBlob(plain)
	var out windows.DataBlob
	err := windows.CryptProtectData(in, nil, nil, 0, nil, 0, &out)
	runtime.KeepAlive(plain)
	if err != nil {
		return nil, err
	}
	return dataBlobBytes(out), nil
}

func dpapiCryptUnprotect(ciphertext []byte) ([]byte, error) {
	in := bytesToDataBlob(ciphertext)
	var out windows.DataBlob
	err := windows.CryptUnprotectData(in, nil, nil, 0, nil, 0, &out)
	runtime.KeepAlive(ciphertext)
	if err != nil {
		return nil, err
	}
	return dataBlobBytes(out), nil
}

func bytesToDataBlob(data []byte) *windows.DataBlob {
	if len(data) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
}

func dataBlobBytes(blob windows.DataBlob) []byte {
	if blob.Size == 0 || blob.Data == nil {
		return nil
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(blob.Data)))
	return append([]byte(nil), unsafe.Slice(blob.Data, int(blob.Size))...)
}
