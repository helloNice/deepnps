package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/servercfg"
)

var (
	ErrDeviceEnrollmentDisabled     = errors.New("device enrollment is disabled")
	ErrDeviceEnrollmentRateLimited  = errors.New("device enrollment rate limited")
	ErrDeviceChallengeNotFound      = errors.New("device enrollment challenge not found")
	ErrDeviceChallengeExpired       = errors.New("device enrollment challenge expired")
	ErrDevicePublicKeyRequired      = errors.New("device public key is required")
	ErrDevicePublicKeyInvalid       = errors.New("device public key is invalid")
	ErrDeviceSignatureInvalid       = errors.New("device signature is invalid")
	ErrDeviceChallengeAlreadyUsed   = errors.New("device enrollment challenge already used")
	ErrDeviceEnrollmentCreateFailed = errors.New("device enrollment client create failed")
)

const (
	defaultDeviceEnrollmentChallengeTTL = 5 * time.Minute
	defaultDeviceEnrollmentRateWindow   = time.Minute
	defaultDeviceEnrollmentRateLimit    = 20
	deviceEnrollmentMaxTunnelNum        = 3
)

type DeviceEnrollmentService interface {
	CreateChallenge(DeviceEnrollmentChallengeInput) (DeviceEnrollmentChallenge, error)
	Complete(DeviceEnrollmentCompleteInput) (DeviceEnrollmentResult, error)
}

type DeviceEnrollmentChallengeInput struct {
	RemoteAddr string
}

type DeviceEnrollmentCompleteInput struct {
	RemoteAddr   string
	ChallengeID  string
	PublicKey    string
	Signature    string
	DeviceName   string
	DeviceRemark string
}

type DeviceEnrollmentChallenge struct {
	ID        string
	Nonce     string
	ExpiresAt int64
	Message   string
}

type DeviceEnrollmentResult struct {
	ClientID  int
	VerifyKey string
	KeyID     string
	Created   bool
}

type DefaultDeviceEnrollmentService struct {
	ConfigProvider func() *servercfg.Snapshot
	Repo           ClientRepository
	Backend        Backend
	ChallengeTTL   time.Duration
	RateWindow     time.Duration
	RateLimit      int
	Now            func() time.Time
	Random         func([]byte) (int, error)

	mu         sync.Mutex
	challenges map[string]deviceEnrollmentChallengeState
	rate       map[string]deviceEnrollmentRateState
}

type deviceEnrollmentChallengeState struct {
	Challenge DeviceEnrollmentChallenge
	Used      bool
}

type deviceEnrollmentRateState struct {
	WindowStart time.Time
	Count       int
}

func NewDefaultDeviceEnrollmentService(configProvider func() *servercfg.Snapshot, repo Repository, backend Backend) *DefaultDeviceEnrollmentService {
	return &DefaultDeviceEnrollmentService{
		ConfigProvider: configProvider,
		Repo:           repo,
		Backend:        backend,
		ChallengeTTL:   defaultDeviceEnrollmentChallengeTTL,
		RateWindow:     defaultDeviceEnrollmentRateWindow,
		RateLimit:      defaultDeviceEnrollmentRateLimit,
	}
}

func (s *DefaultDeviceEnrollmentService) CreateChallenge(input DeviceEnrollmentChallengeInput) (DeviceEnrollmentChallenge, error) {
	if !deviceEnrollmentEnabled(s.config()) {
		return DeviceEnrollmentChallenge{}, ErrDeviceEnrollmentDisabled
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.allowRequestLocked(input.RemoteAddr, now) {
		return DeviceEnrollmentChallenge{}, ErrDeviceEnrollmentRateLimited
	}
	s.cleanupChallengesLocked(now)
	id, err := s.randomToken(24)
	if err != nil {
		return DeviceEnrollmentChallenge{}, err
	}
	nonce, err := s.randomToken(32)
	if err != nil {
		return DeviceEnrollmentChallenge{}, err
	}
	ttl := s.ChallengeTTL
	if ttl <= 0 {
		ttl = defaultDeviceEnrollmentChallengeTTL
	}
	challenge := DeviceEnrollmentChallenge{
		ID:        id,
		Nonce:     nonce,
		ExpiresAt: now.Add(ttl).Unix(),
	}
	challenge.Message = DeviceEnrollmentMessage(challenge.ID, challenge.Nonce)
	if s.challenges == nil {
		s.challenges = make(map[string]deviceEnrollmentChallengeState)
	}
	s.challenges[challenge.ID] = deviceEnrollmentChallengeState{Challenge: challenge}
	return challenge, nil
}

func (s *DefaultDeviceEnrollmentService) Complete(input DeviceEnrollmentCompleteInput) (DeviceEnrollmentResult, error) {
	if !deviceEnrollmentEnabled(s.config()) {
		return DeviceEnrollmentResult{}, ErrDeviceEnrollmentDisabled
	}
	now := s.now()
	publicKey, publicKeyText, keyID, err := normalizeDevicePublicKey(input.PublicKey)
	if err != nil {
		return DeviceEnrollmentResult{}, err
	}
	signature, err := decodeBase64(input.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return DeviceEnrollmentResult{}, ErrDeviceSignatureInvalid
	}
	challenge, err := s.consumeChallenge(input.ChallengeID, input.RemoteAddr, now)
	if err != nil {
		return DeviceEnrollmentResult{}, err
	}
	if !ed25519.Verify(publicKey, []byte(challenge.Message), signature) {
		return DeviceEnrollmentResult{}, ErrDeviceSignatureInvalid
	}
	return s.enrollVerifiedDevice(publicKeyText, keyID, input, now)
}

func (s *DefaultDeviceEnrollmentService) enrollVerifiedDevice(publicKeyText, keyID string, input DeviceEnrollmentCompleteInput, now time.Time) (DeviceEnrollmentResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.findClientByDevicePublicKey(publicKeyText); existing != nil {
		return DeviceEnrollmentResult{ClientID: existing.Id, VerifyKey: existing.VerifyKey, KeyID: keyID}, nil
	}
	client := &file.Client{
		Id:               s.repo().NextClientID(),
		VerifyKey:        "",
		Status:           true,
		Remark:           deviceEnrollmentRemark(input),
		Cnf:              &file.Config{},
		Flow:             &file.Flow{},
		ConfigConnAllow:  true,
		MaxTunnelNum:     deviceEnrollmentMaxTunnelNum,
		DevicePublicKey:  publicKeyText,
		DeviceKeyID:      keyID,
		DeviceEnrolledAt: now.Unix(),
		CreateTime:       now.Format("2006-01-02 15:04:05"),
	}
	client.TouchMeta("device_enrollment", "", keyID)
	if err := s.repo().CreateClient(client); err != nil {
		return DeviceEnrollmentResult{}, errors.Join(ErrDeviceEnrollmentCreateFailed, err)
	}
	return DeviceEnrollmentResult{ClientID: client.Id, VerifyKey: client.VerifyKey, KeyID: keyID, Created: true}, nil
}

func DeviceEnrollmentMessage(challengeID, nonce string) string {
	return "deepnps-device-enrollment\n" + strings.TrimSpace(challengeID) + "\n" + strings.TrimSpace(nonce)
}

func (s *DefaultDeviceEnrollmentService) consumeChallenge(challengeID, remoteAddr string, now time.Time) (DeviceEnrollmentChallenge, error) {
	challengeID = strings.TrimSpace(challengeID)
	if challengeID == "" {
		return DeviceEnrollmentChallenge{}, ErrDeviceChallengeNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.allowRequestLocked(remoteAddr, now) {
		return DeviceEnrollmentChallenge{}, ErrDeviceEnrollmentRateLimited
	}
	state, ok := s.challenges[challengeID]
	if !ok {
		return DeviceEnrollmentChallenge{}, ErrDeviceChallengeNotFound
	}
	if state.Used {
		return DeviceEnrollmentChallenge{}, ErrDeviceChallengeAlreadyUsed
	}
	if state.Challenge.ExpiresAt <= now.Unix() {
		delete(s.challenges, challengeID)
		return DeviceEnrollmentChallenge{}, ErrDeviceChallengeExpired
	}
	state.Used = true
	s.challenges[challengeID] = state
	return state.Challenge, nil
}

func (s *DefaultDeviceEnrollmentService) allowRequestLocked(remoteAddr string, now time.Time) bool {
	limit := s.RateLimit
	if limit <= 0 {
		limit = defaultDeviceEnrollmentRateLimit
	}
	window := s.RateWindow
	if window <= 0 {
		window = defaultDeviceEnrollmentRateWindow
	}
	key := strings.TrimSpace(remoteAddr)
	if key == "" {
		key = "unknown"
	}
	if s.rate == nil {
		s.rate = make(map[string]deviceEnrollmentRateState)
	}
	s.cleanupRateLocked(now, window)
	current := s.rate[key]
	if current.WindowStart.IsZero() || now.Sub(current.WindowStart) >= window {
		s.rate[key] = deviceEnrollmentRateState{WindowStart: now, Count: 1}
		return true
	}
	if current.Count >= limit {
		return false
	}
	current.Count++
	s.rate[key] = current
	return true
}

func (s *DefaultDeviceEnrollmentService) cleanupRateLocked(now time.Time, window time.Duration) {
	if window <= 0 {
		window = defaultDeviceEnrollmentRateWindow
	}
	for key, state := range s.rate {
		if state.WindowStart.IsZero() || now.Sub(state.WindowStart) >= window {
			delete(s.rate, key)
		}
	}
}

func (s *DefaultDeviceEnrollmentService) cleanupChallengesLocked(now time.Time) {
	for id, state := range s.challenges {
		if state.Used || state.Challenge.ExpiresAt <= now.Unix() {
			delete(s.challenges, id)
		}
	}
}

func (s *DefaultDeviceEnrollmentService) findClientByDevicePublicKey(publicKey string) *file.Client {
	var matched *file.Client
	s.repo().RangeClients(func(client *file.Client) bool {
		if client != nil && strings.TrimSpace(client.DevicePublicKey) == publicKey {
			matched = client
			return false
		}
		return true
	})
	return matched
}

func (s *DefaultDeviceEnrollmentService) randomToken(size int) (string, error) {
	buf := make([]byte, size)
	random := s.Random
	if random == nil {
		random = rand.Read
	}
	if _, err := random(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *DefaultDeviceEnrollmentService) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *DefaultDeviceEnrollmentService) config() *servercfg.Snapshot {
	return servercfg.ResolveProvider(s.ConfigProvider)
}

func (s *DefaultDeviceEnrollmentService) repo() ClientRepository {
	if !isNilServiceValue(s.Repo) {
		return s.Repo
	}
	if !isNilServiceValue(s.Backend.Repository) {
		return s.Backend.Repository
	}
	return DefaultBackend().Repository
}

func deviceEnrollmentEnabled(cfg *servercfg.Snapshot) bool {
	return cfg != nil && cfg.Feature.AllowDeviceEnrollment
}

func normalizeDevicePublicKey(value string) (ed25519.PublicKey, string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, "", "", ErrDevicePublicKeyRequired
	}
	raw, err := decodeBase64(value)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, "", "", ErrDevicePublicKeyInvalid
	}
	canonical := base64.RawStdEncoding.EncodeToString(raw)
	sum := sha256.Sum256(raw)
	return ed25519.PublicKey(raw), canonical, hex.EncodeToString(sum[:8]), nil
}

func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty base64 value")
	}
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
		if decoded, err := enc.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("invalid base64 value")
}

func deviceEnrollmentRemark(input DeviceEnrollmentCompleteInput) string {
	if remark := strings.TrimSpace(input.DeviceRemark); remark != "" {
		return remark
	}
	if name := strings.TrimSpace(input.DeviceName); name != "" {
		return name
	}
	return "DeepNPS device"
}
