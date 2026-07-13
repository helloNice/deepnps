package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	deviceIdentityStateVersion = 1
	deviceIdentityFileName     = "device.json"
)

var (
	ErrDeviceIdentityMissingPrivateKey = errors.New("device identity private key is missing")
	ErrDeviceIdentityInvalidPrivateKey = errors.New("device identity private key is invalid")
	ErrDeviceIdentityInvalidPublicKey  = errors.New("device identity public key does not match private key")
	ErrDeviceEnrollmentNotStored       = errors.New("device enrollment credentials are not stored")
)

type DeviceSecretProtector interface {
	Protect([]byte) ([]byte, error)
	Unprotect([]byte) ([]byte, error)
	Name() string
}

type DeviceIdentityStoreOptions struct {
	RootDir   string
	FileName  string
	Protector DeviceSecretProtector
	Now       func() time.Time
	Random    io.Reader
}

type DeviceIdentityStore struct {
	rootDir   string
	fileName  string
	protector DeviceSecretProtector
	now       func() time.Time
	random    io.Reader
}

type DeviceIdentity struct {
	state      deviceIdentityState
	privateKey ed25519.PrivateKey
	protector  DeviceSecretProtector
	now        func() time.Time
	path       string
}

type DeviceEnrollmentCredentials struct {
	Server   string `json:"server,omitempty"`
	ClientID int    `json:"client_id,omitempty"`
	VKey     string `json:"-"`
}

type DeviceEnrollmentUpdate struct {
	Server     string
	ClientID   int
	VerifyKey  string
	EnrolledAt time.Time
}

type deviceIdentityState struct {
	Version              int    `json:"version"`
	PublicKey            string `json:"public_key"`
	KeyID                string `json:"key_id"`
	PrivateKeyCiphertext string `json:"private_key_ciphertext"`
	PrivateKeyProtector  string `json:"private_key_protector"`
	Server               string `json:"server,omitempty"`
	ClientID             int    `json:"client_id,omitempty"`
	VerifyKeyCiphertext  string `json:"verify_key_ciphertext,omitempty"`
	VerifyKeyProtector   string `json:"verify_key_protector,omitempty"`
	EnrolledAt           int64  `json:"enrolled_at,omitempty"`
	UpdatedAt            int64  `json:"updated_at,omitempty"`
}

func NewDeviceIdentityStore(options DeviceIdentityStoreOptions) *DeviceIdentityStore {
	rootDir := strings.TrimSpace(options.RootDir)
	if rootDir == "" {
		rootDir = DefaultDeviceIdentityDir()
	}
	fileName := strings.TrimSpace(options.FileName)
	if fileName == "" {
		fileName = deviceIdentityFileName
	}
	protector := options.Protector
	if protector == nil {
		protector = defaultDeviceSecretProtector(rootDir)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	return &DeviceIdentityStore{
		rootDir:   rootDir,
		fileName:  fileName,
		protector: protector,
		now:       now,
		random:    random,
	}
}

func DefaultDeviceIdentityDir() string {
	if dir := defaultDeviceIdentityBaseDir(); strings.TrimSpace(dir) != "" {
		return filepath.Join(dir, "DeepNPS")
	}
	return filepath.Join(os.TempDir(), "DeepNPS")
}

func (s *DeviceIdentityStore) Path() string {
	if s == nil {
		return filepath.Join(DefaultDeviceIdentityDir(), deviceIdentityFileName)
	}
	return filepath.Join(s.rootDir, s.fileName)
}

func (s *DeviceIdentityStore) Load() (*DeviceIdentity, error) {
	if s == nil {
		s = NewDeviceIdentityStore(DeviceIdentityStoreOptions{})
	}
	return s.load(s.Path())
}

func (s *DeviceIdentityStore) LoadOrCreate() (*DeviceIdentity, bool, error) {
	if s == nil {
		s = NewDeviceIdentityStore(DeviceIdentityStoreOptions{})
	}
	path := s.Path()
	identity, err := s.load(path)
	if err == nil {
		return identity, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	identity, err = s.create(path)
	if err != nil {
		return nil, false, err
	}
	return identity, true, nil
}

func (s *DeviceIdentityStore) load(path string) (*DeviceIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state deviceIdentityState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	privateKey, err := decryptPrivateKey(s.protector, state)
	if err != nil {
		return nil, err
	}
	if err := validateDeviceKeyPair(privateKey, state.PublicKey); err != nil {
		return nil, err
	}
	if strings.TrimSpace(state.KeyID) == "" {
		state.KeyID = deviceKeyID(privateKey.Public().(ed25519.PublicKey))
	}
	return &DeviceIdentity{
		state:      state,
		privateKey: privateKey,
		protector:  s.protector,
		now:        s.now,
		path:       path,
	}, nil
}

func (s *DeviceIdentityStore) create(path string) (*DeviceIdentity, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(s.random)
	if err != nil {
		return nil, err
	}
	ciphertext, err := s.protector.Protect([]byte(privateKey))
	if err != nil {
		return nil, err
	}
	now := s.now().Unix()
	state := deviceIdentityState{
		Version:              deviceIdentityStateVersion,
		PublicKey:            encodeDeviceBytes(publicKey),
		KeyID:                deviceKeyID(publicKey),
		PrivateKeyCiphertext: encodeDeviceBytes(ciphertext),
		PrivateKeyProtector:  s.protector.Name(),
		UpdatedAt:            now,
	}
	identity := &DeviceIdentity{
		state:      state,
		privateKey: privateKey,
		protector:  s.protector,
		now:        s.now,
		path:       path,
	}
	if err := identity.save(); err != nil {
		return nil, err
	}
	return identity, nil
}

func (i *DeviceIdentity) PublicKeyBase64() string {
	if i == nil {
		return ""
	}
	return i.state.PublicKey
}

func (i *DeviceIdentity) KeyID() string {
	if i == nil {
		return ""
	}
	return i.state.KeyID
}

func (i *DeviceIdentity) Sign(message string) (string, error) {
	if i == nil || len(i.privateKey) != ed25519.PrivateKeySize {
		return "", ErrDeviceIdentityMissingPrivateKey
	}
	signature := ed25519.Sign(i.privateKey, []byte(message))
	return encodeDeviceBytes(signature), nil
}

func (i *DeviceIdentity) StoreEnrollment(update DeviceEnrollmentUpdate) error {
	if i == nil {
		return ErrDeviceIdentityMissingPrivateKey
	}
	verifyKey := strings.TrimSpace(update.VerifyKey)
	if verifyKey == "" {
		return ErrDeviceEnrollmentNotStored
	}
	ciphertext, err := i.protector.Protect([]byte(verifyKey))
	if err != nil {
		return err
	}
	enrolledAt := update.EnrolledAt
	if enrolledAt.IsZero() {
		enrolledAt = i.now()
	}
	i.state.Server = strings.TrimSpace(update.Server)
	i.state.ClientID = update.ClientID
	i.state.VerifyKeyCiphertext = encodeDeviceBytes(ciphertext)
	i.state.VerifyKeyProtector = i.protector.Name()
	i.state.EnrolledAt = enrolledAt.Unix()
	i.state.UpdatedAt = i.now().Unix()
	return i.save()
}

func (i *DeviceIdentity) EnrollmentCredentials() (DeviceEnrollmentCredentials, error) {
	if i == nil || strings.TrimSpace(i.state.VerifyKeyCiphertext) == "" {
		return DeviceEnrollmentCredentials{}, ErrDeviceEnrollmentNotStored
	}
	ciphertext, err := decodeDeviceBytes(i.state.VerifyKeyCiphertext)
	if err != nil {
		return DeviceEnrollmentCredentials{}, err
	}
	plain, err := i.protector.Unprotect(ciphertext)
	if err != nil {
		return DeviceEnrollmentCredentials{}, err
	}
	vkey := strings.TrimSpace(string(plain))
	if vkey == "" {
		return DeviceEnrollmentCredentials{}, ErrDeviceEnrollmentNotStored
	}
	return DeviceEnrollmentCredentials{
		Server:   i.state.Server,
		ClientID: i.state.ClientID,
		VKey:     vkey,
	}, nil
}

func (i *DeviceIdentity) StateSnapshot() map[string]interface{} {
	if i == nil {
		return nil
	}
	out := map[string]interface{}{
		"version":     i.state.Version,
		"public_key":  i.state.PublicKey,
		"key_id":      i.state.KeyID,
		"server":      i.state.Server,
		"client_id":   i.state.ClientID,
		"enrolled_at": i.state.EnrolledAt,
		"updated_at":  i.state.UpdatedAt,
	}
	return out
}

func (i *DeviceIdentity) save() error {
	if i == nil {
		return ErrDeviceIdentityMissingPrivateKey
	}
	i.state.Version = deviceIdentityStateVersion
	if strings.TrimSpace(i.state.KeyID) == "" {
		i.state.KeyID = deviceKeyID(i.privateKey.Public().(ed25519.PublicKey))
	}
	if err := os.MkdirAll(filepath.Dir(i.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(i.state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeDeviceIdentityFile(i.path, data)
}

func decryptPrivateKey(protector DeviceSecretProtector, state deviceIdentityState) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(state.PrivateKeyCiphertext) == "" {
		return nil, ErrDeviceIdentityMissingPrivateKey
	}
	ciphertext, err := decodeDeviceBytes(state.PrivateKeyCiphertext)
	if err != nil {
		return nil, err
	}
	plain, err := protector.Unprotect(ciphertext)
	if err != nil {
		return nil, err
	}
	if len(plain) != ed25519.PrivateKeySize {
		return nil, ErrDeviceIdentityInvalidPrivateKey
	}
	return ed25519.PrivateKey(plain), nil
}

func validateDeviceKeyPair(privateKey ed25519.PrivateKey, publicKeyText string) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return ErrDeviceIdentityInvalidPrivateKey
	}
	publicKey, err := decodeDeviceBytes(publicKeyText)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return ErrDeviceIdentityInvalidPublicKey
	}
	actual := privateKey.Public().(ed25519.PublicKey)
	if !equalDeviceBytes(actual, publicKey) {
		return ErrDeviceIdentityInvalidPublicKey
	}
	return nil
}

func deviceKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:8])
}

func encodeDeviceBytes(value []byte) string {
	return base64.RawStdEncoding.EncodeToString(value)
}

func decodeDeviceBytes(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("empty base64 value")
	}
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
		if decoded, err := enc.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 value")
}

func equalDeviceBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func writeDeviceIdentityFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".device-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return replaceDeviceIdentityFile(tmpPath, path)
}
