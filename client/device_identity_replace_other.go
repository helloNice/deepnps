//go:build !windows

package client

import "os"

func replaceDeviceIdentityFile(tmpPath, path string) error {
	return os.Rename(tmpPath, path)
}
