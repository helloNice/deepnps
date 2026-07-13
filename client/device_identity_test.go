package client

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type xorDeviceSecretProtector struct {
	key byte
}

func (p xorDeviceSecretProtector) Name() string {
	return "xor-test"
}

func (p xorDeviceSecretProtector) Protect(plain []byte) ([]byte, error) {
	return p.apply(plain), nil
}

func (p xorDeviceSecretProtector) Unprotect(ciphertext []byte) ([]byte, error) {
	return p.apply(ciphertext), nil
}

func (p xorDeviceSecretProtector) apply(input []byte) []byte {
	out := append([]byte(nil), input...)
	for i := range out {
		out[i] ^= p.key
	}
	return out
}

func TestDeviceIdentityStoreCreatesAndReloadsStableIdentity(t *testing.T) {
	root := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	store := NewDeviceIdentityStore(DeviceIdentityStoreOptions{
		RootDir:   root,
		Protector: xorDeviceSecretProtector{key: 0x5a},
		Now:       func() time.Time { return now },
	})

	identity, created, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate(create) error = %v", err)
	}
	if !created {
		t.Fatal("LoadOrCreate(create) created = false, want true")
	}
	if identity.PublicKeyBase64() == "" || identity.KeyID() == "" {
		t.Fatalf("identity public key/key id = %q/%q", identity.PublicKeyBase64(), identity.KeyID())
	}
	path := filepath.Join(root, deviceIdentityFileName)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state file missing: %v", err)
	}

	reloaded, created, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate(reload) error = %v", err)
	}
	if created {
		t.Fatal("LoadOrCreate(reload) created = true, want false")
	}
	if reloaded.PublicKeyBase64() != identity.PublicKeyBase64() || reloaded.KeyID() != identity.KeyID() {
		t.Fatalf("reloaded identity = %q/%q, want %q/%q", reloaded.PublicKeyBase64(), reloaded.KeyID(), identity.PublicKeyBase64(), identity.KeyID())
	}
}

func TestDeviceIdentitySignsWithoutExposingPrivateKey(t *testing.T) {
	store := NewDeviceIdentityStore(DeviceIdentityStoreOptions{
		RootDir:   t.TempDir(),
		Protector: xorDeviceSecretProtector{key: 0xa5},
	})
	identity, _, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}
	message := "deepnps-device-enrollment\nchallenge\nnonce"
	signatureText, err := identity.Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	publicKey, err := decodeDeviceBytes(identity.PublicKeyBase64())
	if err != nil {
		t.Fatalf("decode public key error = %v", err)
	}
	signature, err := decodeDeviceBytes(signatureText)
	if err != nil {
		t.Fatalf("decode signature error = %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(message), signature) {
		t.Fatal("signature does not verify")
	}

	raw, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("ReadFile(state) error = %v", err)
	}
	if strings.Contains(string(raw), "private_key\"") || strings.Contains(string(raw), "vkey") {
		t.Fatalf("state file exposes forbidden field names: %s", string(raw))
	}
	var state map[string]interface{}
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("state json error = %v", err)
	}
	if _, ok := state["private_key_ciphertext"]; !ok {
		t.Fatalf("state missing private_key_ciphertext: %v", state)
	}
}

func TestDeviceIdentityStoresEnrollmentCredentialsEncrypted(t *testing.T) {
	now := time.Unix(1_700_000_100, 0)
	store := NewDeviceIdentityStore(DeviceIdentityStoreOptions{
		RootDir:   t.TempDir(),
		Protector: xorDeviceSecretProtector{key: 0x33},
		Now:       func() time.Time { return now },
	})
	identity, _, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}
	if _, err := identity.EnrollmentCredentials(); !errors.Is(err, ErrDeviceEnrollmentNotStored) {
		t.Fatalf("EnrollmentCredentials() error = %v, want not stored", err)
	}
	if err := identity.StoreEnrollment(DeviceEnrollmentUpdate{
		Server:    "127.0.0.1:8024",
		ClientID:  42,
		VerifyKey: "secret-vkey",
	}); err != nil {
		t.Fatalf("StoreEnrollment() error = %v", err)
	}

	reloaded, _, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate(reload) error = %v", err)
	}
	credentials, err := reloaded.EnrollmentCredentials()
	if err != nil {
		t.Fatalf("EnrollmentCredentials() error = %v", err)
	}
	if credentials.Server != "127.0.0.1:8024" || credentials.ClientID != 42 || credentials.VKey != "secret-vkey" {
		t.Fatalf("credentials = %+v", credentials)
	}
	credentialJSON, err := json.Marshal(credentials)
	if err != nil {
		t.Fatalf("Marshal(credentials) error = %v", err)
	}
	if strings.Contains(string(credentialJSON), "secret-vkey") || strings.Contains(string(credentialJSON), "VKey") {
		t.Fatalf("credential json exposes verify key: %s", string(credentialJSON))
	}
	raw, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("ReadFile(state) error = %v", err)
	}
	if strings.Contains(string(raw), "secret-vkey") || strings.Contains(string(raw), "\"vkey\"") {
		t.Fatalf("state file exposes verify key: %s", string(raw))
	}
}

func TestDeviceIdentitySaveReplacesExistingStateFile(t *testing.T) {
	store := NewDeviceIdentityStore(DeviceIdentityStoreOptions{
		RootDir:   t.TempDir(),
		Protector: xorDeviceSecretProtector{key: 0x44},
	})
	identity, _, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}
	if err := identity.StoreEnrollment(DeviceEnrollmentUpdate{
		Server:    "first.example:8024",
		ClientID:  1,
		VerifyKey: "first-vkey",
	}); err != nil {
		t.Fatalf("StoreEnrollment(first) error = %v", err)
	}
	if err := identity.StoreEnrollment(DeviceEnrollmentUpdate{
		Server:    "second.example:8024",
		ClientID:  2,
		VerifyKey: "second-vkey",
	}); err != nil {
		t.Fatalf("StoreEnrollment(second) error = %v", err)
	}
	reloaded, _, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate(reload) error = %v", err)
	}
	credentials, err := reloaded.EnrollmentCredentials()
	if err != nil {
		t.Fatalf("EnrollmentCredentials() error = %v", err)
	}
	if credentials.Server != "second.example:8024" || credentials.ClientID != 2 || credentials.VKey != "second-vkey" {
		t.Fatalf("credentials after replace = %+v", credentials)
	}
}

func TestDefaultDeviceSecretProtectorDoesNotStorePlaintextSecrets(t *testing.T) {
	store := NewDeviceIdentityStore(DeviceIdentityStoreOptions{RootDir: t.TempDir()})
	identity, _, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}
	if err := identity.StoreEnrollment(DeviceEnrollmentUpdate{
		Server:    "127.0.0.1:8024",
		ClientID:  7,
		VerifyKey: "default-secret-vkey",
	}); err != nil {
		t.Fatalf("StoreEnrollment() error = %v", err)
	}
	var state deviceIdentityState
	raw, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("ReadFile(state) error = %v", err)
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("Unmarshal(state) error = %v", err)
	}
	privateCiphertext, err := decodeDeviceBytes(state.PrivateKeyCiphertext)
	if err != nil {
		t.Fatalf("decode private ciphertext error = %v", err)
	}
	verifyCiphertext, err := decodeDeviceBytes(state.VerifyKeyCiphertext)
	if err != nil {
		t.Fatalf("decode verify ciphertext error = %v", err)
	}
	if equalDeviceBytes(privateCiphertext, identity.privateKey) {
		t.Fatal("default protector stored private key as reversible base64 plaintext")
	}
	if string(verifyCiphertext) == "default-secret-vkey" {
		t.Fatal("default protector stored verify key as reversible base64 plaintext")
	}
}

func TestDeviceIdentityRejectsCorruptState(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, deviceIdentityFileName), []byte(`{"public_key":"bad","private_key_ciphertext":"bad"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(corrupt state) error = %v", err)
	}
	store := NewDeviceIdentityStore(DeviceIdentityStoreOptions{
		RootDir:   root,
		Protector: xorDeviceSecretProtector{key: 0x11},
	})
	if _, _, err := store.LoadOrCreate(); err == nil {
		t.Fatal("LoadOrCreate(corrupt) error = nil, want error")
	}
}
