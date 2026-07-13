//go:build windows

package client

import (
	"os"
	"path/filepath"
)

func defaultDeviceIdentityBaseDir() string {
	if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
		return dir
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return dir
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, "AppData", "Local")
	}
	return ""
}
