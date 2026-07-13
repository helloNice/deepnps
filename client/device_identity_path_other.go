//go:build !windows

package client

import "os"

func defaultDeviceIdentityBaseDir() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return dir
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home
	}
	return ""
}
