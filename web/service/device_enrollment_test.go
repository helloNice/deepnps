package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/servercfg"
)

func TestDeviceEnrollmentCompletesAndCreatesLimitedClient(t *testing.T) {
	clients := make([]*file.Client, 0)
	repo := stubRepository{
		nextClientID: func() int { return 41 },
		createClient: func(client *file.Client) error {
			if client.VerifyKey == "" {
				client.VerifyKey = "server-assigned-vkey"
			}
			clients = append(clients, client)
			return nil
		},
		rangeClients: func(fn func(*file.Client) bool) {
			for _, client := range clients {
				if !fn(client) {
					return
				}
			}
		},
	}
	now := time.Unix(1_700_000_000, 0)
	service := NewDefaultDeviceEnrollmentService(func() *servercfg.Snapshot {
		return &servercfg.Snapshot{Feature: servercfg.FeatureConfig{AllowDeviceEnrollment: true}}
	}, repo, Backend{Repository: repo})
	service.Now = func() time.Time { return now }

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	challenge, err := service.CreateChallenge(DeviceEnrollmentChallengeInput{RemoteAddr: "127.0.0.1"})
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}
	signature := ed25519.Sign(privateKey, []byte(challenge.Message))

	result, err := service.Complete(DeviceEnrollmentCompleteInput{
		RemoteAddr:  "127.0.0.1",
		ChallengeID: challenge.ID,
		PublicKey:   base64.RawStdEncoding.EncodeToString(publicKey),
		Signature:   base64.RawStdEncoding.EncodeToString(signature),
		DeviceName:  "workstation-a",
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if !result.Created || result.ClientID != 41 || result.VerifyKey != "server-assigned-vkey" {
		t.Fatalf("Complete() result = %+v, want created client 41 with assigned vkey", result)
	}
	if len(clients) != 1 {
		t.Fatalf("created clients = %d, want 1", len(clients))
	}
	client := clients[0]
	if client.MaxTunnelNum != 3 {
		t.Fatalf("client.MaxTunnelNum = %d, want 3", client.MaxTunnelNum)
	}
	if !client.ConfigConnAllow || !client.Status {
		t.Fatalf("client status/config allow = %v/%v, want true/true", client.Status, client.ConfigConnAllow)
	}
	if client.DevicePublicKey == "" || client.DeviceKeyID == "" || client.DeviceEnrolledAt != now.Unix() {
		t.Fatalf("device identity fields = public:%q key:%q at:%d", client.DevicePublicKey, client.DeviceKeyID, client.DeviceEnrolledAt)
	}
}

func TestDeviceEnrollmentDeduplicatesPublicKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	_, publicKeyText, keyID, err := normalizeDevicePublicKey(base64.RawStdEncoding.EncodeToString(publicKey))
	if err != nil {
		t.Fatalf("normalizeDevicePublicKey() error = %v", err)
	}
	existing := &file.Client{Id: 7, VerifyKey: "existing-vkey", DevicePublicKey: publicKeyText}
	createCalls := 0
	repo := stubRepository{
		createClient: func(*file.Client) error {
			createCalls++
			return nil
		},
		rangeClients: func(fn func(*file.Client) bool) {
			fn(existing)
		},
	}
	service := NewDefaultDeviceEnrollmentService(func() *servercfg.Snapshot {
		return &servercfg.Snapshot{Feature: servercfg.FeatureConfig{AllowDeviceEnrollment: true}}
	}, repo, Backend{Repository: repo})

	challenge, err := service.CreateChallenge(DeviceEnrollmentChallengeInput{RemoteAddr: "127.0.0.1"})
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}
	result, err := service.Complete(DeviceEnrollmentCompleteInput{
		RemoteAddr:  "127.0.0.1",
		ChallengeID: challenge.ID,
		PublicKey:   base64.RawStdEncoding.EncodeToString(publicKey),
		Signature:   base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(challenge.Message))),
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if result.Created || result.ClientID != existing.Id || result.VerifyKey != existing.VerifyKey || result.KeyID != keyID {
		t.Fatalf("Complete() result = %+v, want existing client with key id %s", result, keyID)
	}
	if createCalls != 0 {
		t.Fatalf("CreateClient calls = %d, want 0 for duplicate public key", createCalls)
	}
}

func TestDeviceEnrollmentDeduplicatesConcurrentCompletions(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	clients := make([]*file.Client, 0)
	nextID := 100
	createCalls := 0
	repo := stubRepository{
		nextClientID: func() int {
			nextID++
			return nextID
		},
		createClient: func(client *file.Client) error {
			createCalls++
			client.VerifyKey = "vkey-concurrent"
			clients = append(clients, client)
			return nil
		},
		rangeClients: func(fn func(*file.Client) bool) {
			for _, client := range clients {
				if !fn(client) {
					return
				}
			}
		},
	}
	service := NewDefaultDeviceEnrollmentService(func() *servercfg.Snapshot {
		return &servercfg.Snapshot{Feature: servercfg.FeatureConfig{AllowDeviceEnrollment: true}}
	}, repo, Backend{Repository: repo})

	first, err := service.CreateChallenge(DeviceEnrollmentChallengeInput{RemoteAddr: "127.0.0.1"})
	if err != nil {
		t.Fatalf("CreateChallenge(first) error = %v", err)
	}
	second, err := service.CreateChallenge(DeviceEnrollmentChallengeInput{RemoteAddr: "127.0.0.1"})
	if err != nil {
		t.Fatalf("CreateChallenge(second) error = %v", err)
	}
	challenges := []DeviceEnrollmentChallenge{first, second}
	results := make([]DeviceEnrollmentResult, len(challenges))
	errs := make([]error, len(challenges))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, challenge := range challenges {
		wg.Add(1)
		go func(index int, challenge DeviceEnrollmentChallenge) {
			defer wg.Done()
			<-start
			results[index], errs[index] = service.Complete(DeviceEnrollmentCompleteInput{
				RemoteAddr:  "127.0.0.1",
				ChallengeID: challenge.ID,
				PublicKey:   base64.RawStdEncoding.EncodeToString(publicKey),
				Signature:   base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(challenge.Message))),
			})
		}(i, challenge)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Complete(%d) error = %v", i, err)
		}
	}
	if createCalls != 1 || len(clients) != 1 {
		t.Fatalf("created clients = calls:%d len:%d, want one", createCalls, len(clients))
	}
	if results[0].ClientID != results[1].ClientID || results[0].VerifyKey != results[1].VerifyKey {
		t.Fatalf("concurrent results = %+v / %+v, want same client", results[0], results[1])
	}
}

func TestDeviceEnrollmentPrunesStaleRateLimitEntries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	service := NewDefaultDeviceEnrollmentService(func() *servercfg.Snapshot {
		return &servercfg.Snapshot{Feature: servercfg.FeatureConfig{AllowDeviceEnrollment: true}}
	}, stubRepository{}, Backend{})
	service.Now = func() time.Time { return now }
	service.RateWindow = time.Second

	for _, remoteAddr := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if _, err := service.CreateChallenge(DeviceEnrollmentChallengeInput{RemoteAddr: remoteAddr}); err != nil {
			t.Fatalf("CreateChallenge(%s) error = %v", remoteAddr, err)
		}
	}
	if len(service.rate) != 3 {
		t.Fatalf("rate entries = %d, want 3", len(service.rate))
	}
	now = now.Add(2 * time.Second)
	if _, err := service.CreateChallenge(DeviceEnrollmentChallengeInput{RemoteAddr: "10.0.0.4"}); err != nil {
		t.Fatalf("CreateChallenge(new window) error = %v", err)
	}
	if len(service.rate) != 1 {
		t.Fatalf("rate entries after prune = %d, want 1", len(service.rate))
	}
	if _, ok := service.rate["10.0.0.4"]; !ok {
		t.Fatalf("new rate entry missing after prune: %#v", service.rate)
	}
}

func TestDeviceEnrollmentRejectsDisabledReplayAndBadSignature(t *testing.T) {
	disabled := NewDefaultDeviceEnrollmentService(func() *servercfg.Snapshot {
		return &servercfg.Snapshot{}
	}, stubRepository{}, Backend{})
	if _, err := disabled.CreateChallenge(DeviceEnrollmentChallengeInput{}); !errors.Is(err, ErrDeviceEnrollmentDisabled) {
		t.Fatalf("CreateChallenge() error = %v, want disabled", err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	repo := stubRepository{
		nextClientID: func() int { return 1 },
		createClient: func(client *file.Client) error {
			client.VerifyKey = "vkey"
			return nil
		},
	}
	service := NewDefaultDeviceEnrollmentService(func() *servercfg.Snapshot {
		return &servercfg.Snapshot{Feature: servercfg.FeatureConfig{AllowDeviceEnrollment: true}}
	}, repo, Backend{Repository: repo})
	challenge, err := service.CreateChallenge(DeviceEnrollmentChallengeInput{RemoteAddr: "127.0.0.1"})
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}
	if _, err := service.Complete(DeviceEnrollmentCompleteInput{
		RemoteAddr:  "127.0.0.1",
		ChallengeID: challenge.ID,
		PublicKey:   base64.RawStdEncoding.EncodeToString(publicKey),
		Signature:   base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte("wrong message"))),
	}); !errors.Is(err, ErrDeviceSignatureInvalid) {
		t.Fatalf("Complete(bad signature) error = %v, want invalid signature", err)
	}
	if _, err := service.Complete(DeviceEnrollmentCompleteInput{
		RemoteAddr:  "127.0.0.1",
		ChallengeID: challenge.ID,
		PublicKey:   base64.RawStdEncoding.EncodeToString(publicKey),
		Signature:   base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(challenge.Message))),
	}); !errors.Is(err, ErrDeviceChallengeAlreadyUsed) {
		t.Fatalf("Complete(replay) error = %v, want already used", err)
	}
}
