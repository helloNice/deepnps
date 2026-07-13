//go:build !windows

package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

const (
	fileKeyDeviceSecretKeyName = "device.key"
	fileKeyDeviceSecretVersion = byte(1)
)

type fileKeyDeviceSecretProtector struct {
	keyPath string
}

func defaultDeviceSecretProtector(rootDir string) DeviceSecretProtector {
	return fileKeyDeviceSecretProtector{keyPath: filepath.Join(rootDir, fileKeyDeviceSecretKeyName)}
}

func (p fileKeyDeviceSecretProtector) Name() string {
	return "local-file-aes-gcm"
}

func (p fileKeyDeviceSecretProtector) Protect(plain []byte) ([]byte, error) {
	aead, err := p.aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(nonce)+len(plain)+aead.Overhead())
	out = append(out, fileKeyDeviceSecretVersion)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plain, []byte(p.Name()))
	return out, nil
}

func (p fileKeyDeviceSecretProtector) Unprotect(ciphertext []byte) ([]byte, error) {
	aead, err := p.aead()
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < 1+aead.NonceSize()+aead.Overhead() || ciphertext[0] != fileKeyDeviceSecretVersion {
		return nil, fmt.Errorf("invalid device secret ciphertext")
	}
	nonceStart := 1
	nonceEnd := nonceStart + aead.NonceSize()
	nonce := ciphertext[nonceStart:nonceEnd]
	body := ciphertext[nonceEnd:]
	return aead.Open(nil, nonce, body, []byte(p.Name()))
}

func (p fileKeyDeviceSecretProtector) aead() (cipher.AEAD, error) {
	key, err := p.loadOrCreateKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (p fileKeyDeviceSecretProtector) loadOrCreateKey() ([]byte, error) {
	key, err := os.ReadFile(p.keyPath)
	if err == nil {
		if len(key) != 32 {
			return nil, fmt.Errorf("invalid device secret key length")
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p.keyPath), 0o700); err != nil {
		return nil, err
	}
	if err := writeDeviceIdentityFile(p.keyPath, key); err != nil {
		return nil, err
	}
	return key, nil
}
