package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/djylb/nps/lib/servercfg"
	webservice "github.com/djylb/nps/web/service"
)

type stubDeviceEnrollmentService struct {
	challenge func(webservice.DeviceEnrollmentChallengeInput) (webservice.DeviceEnrollmentChallenge, error)
	complete  func(webservice.DeviceEnrollmentCompleteInput) (webservice.DeviceEnrollmentResult, error)
}

func (s stubDeviceEnrollmentService) CreateChallenge(input webservice.DeviceEnrollmentChallengeInput) (webservice.DeviceEnrollmentChallenge, error) {
	if s.challenge != nil {
		return s.challenge(input)
	}
	return webservice.DeviceEnrollmentChallenge{}, nil
}

func (s stubDeviceEnrollmentService) Complete(input webservice.DeviceEnrollmentCompleteInput) (webservice.DeviceEnrollmentResult, error) {
	if s.complete != nil {
		return s.complete(input)
	}
	return webservice.DeviceEnrollmentResult{}, nil
}

type stubDeviceEnrollmentContext struct {
	stubNodeTrafficContext
	clientIP string
}

func (c *stubDeviceEnrollmentContext) ClientIP() string {
	return c.clientIP
}

func TestSessionActionCatalogPublishesDeviceEnrollmentOnlyWhenEnabled(t *testing.T) {
	cfg := &servercfg.Snapshot{}
	entries := VisibleActionEntries(cfg, "", AnonymousActor(), webservice.DefaultAuthorizationService{}, SessionActionCatalog(&App{}))
	for _, entry := range entries {
		if entry.Resource == "devices" {
			t.Fatalf("device enrollment action visible while disabled: %+v", entry)
		}
	}

	cfg.Feature.AllowDeviceEnrollment = true
	entries = VisibleActionEntries(cfg, "", AnonymousActor(), webservice.DefaultAuthorizationService{}, SessionActionCatalog(&App{}))
	foundChallenge := false
	foundComplete := false
	for _, entry := range entries {
		if entry.Resource == "devices" && entry.Action == "enrollment_challenge" && entry.Path == "/api/devices/enrollment/challenge" {
			foundChallenge = true
		}
		if entry.Resource == "devices" && entry.Action == "enrollment_complete" && entry.Path == "/api/devices/enrollment/complete" {
			foundComplete = true
		}
	}
	if !foundChallenge || !foundComplete {
		t.Fatalf("device enrollment actions visible = challenge:%v complete:%v, want both", foundChallenge, foundComplete)
	}
}

func TestDeviceEnrollmentHandlersUseManagementEnvelope(t *testing.T) {
	app := NewWithOptions(&servercfg.Snapshot{
		Feature: servercfg.FeatureConfig{AllowDeviceEnrollment: true},
	}, Options{
		Services: &webservice.Services{
			DeviceEnrollment: stubDeviceEnrollmentService{
				challenge: func(input webservice.DeviceEnrollmentChallengeInput) (webservice.DeviceEnrollmentChallenge, error) {
					if input.RemoteAddr != "127.0.0.1" {
						t.Fatalf("RemoteAddr = %q, want 127.0.0.1", input.RemoteAddr)
					}
					return webservice.DeviceEnrollmentChallenge{
						ID:        "challenge-1",
						Nonce:     "nonce-1",
						Message:   "message-1",
						ExpiresAt: 123,
					}, nil
				},
			},
		},
	})
	ctx := &stubDeviceEnrollmentContext{clientIP: "127.0.0.1"}
	app.DeviceEnrollmentChallenge(ctx)
	if ctx.status != 200 {
		t.Fatalf("DeviceEnrollmentChallenge() status = %d, want 200", ctx.status)
	}
	response, ok := ctx.jsonPayload.(ManagementDataResponse)
	if !ok {
		t.Fatalf("payload type = %T, want ManagementDataResponse", ctx.jsonPayload)
	}
	data, ok := response.Data.(deviceEnrollmentChallengeResponse)
	if !ok || data.ChallengeID != "challenge-1" || data.Nonce != "nonce-1" || data.ExpiresAt != 123 {
		t.Fatalf("challenge response = %#v", response.Data)
	}

	completeApp := NewWithOptions(&servercfg.Snapshot{
		Feature: servercfg.FeatureConfig{AllowDeviceEnrollment: true},
	}, Options{
		Services: &webservice.Services{
			DeviceEnrollment: stubDeviceEnrollmentService{
				complete: func(input webservice.DeviceEnrollmentCompleteInput) (webservice.DeviceEnrollmentResult, error) {
					if input.ChallengeID != "challenge-1" || input.PublicKey != "pub" || input.Signature != "sig" || input.DeviceName != "pc" {
						t.Fatalf("complete input = %+v", input)
					}
					return webservice.DeviceEnrollmentResult{ClientID: 9, VerifyKey: "vkey", KeyID: "kid", Created: true}, nil
				},
			},
		},
	})
	completeCtx := &stubDeviceEnrollmentContext{
		stubNodeTrafficContext: stubNodeTrafficContext{rawBody: []byte(`{"challenge_id":"challenge-1","public_key":"pub","signature":"sig","device_name":"pc"}`)},
		clientIP:               "127.0.0.1",
	}
	completeApp.DeviceEnrollmentComplete(completeCtx)
	if completeCtx.status != 200 {
		t.Fatalf("DeviceEnrollmentComplete() status = %d, want 200", completeCtx.status)
	}
	completeResponse, ok := completeCtx.jsonPayload.(ManagementDataResponse)
	if !ok {
		t.Fatalf("complete payload type = %T, want ManagementDataResponse", completeCtx.jsonPayload)
	}
	completeData, ok := completeResponse.Data.(deviceEnrollmentCompleteResponse)
	if !ok || completeData.ClientID != 9 || completeData.VerifyKey != "vkey" || completeData.KeyID != "kid" || !completeData.Created {
		t.Fatalf("complete response = %#v", completeResponse.Data)
	}
}

func TestDeviceEnrollmentHandlerMapsRateLimit(t *testing.T) {
	app := NewWithOptions(&servercfg.Snapshot{
		Feature: servercfg.FeatureConfig{AllowDeviceEnrollment: true},
	}, Options{
		Services: &webservice.Services{
			DeviceEnrollment: stubDeviceEnrollmentService{
				challenge: func(webservice.DeviceEnrollmentChallengeInput) (webservice.DeviceEnrollmentChallenge, error) {
					return webservice.DeviceEnrollmentChallenge{}, webservice.ErrDeviceEnrollmentRateLimited
				},
			},
		},
	})
	ctx := &stubDeviceEnrollmentContext{}
	app.DeviceEnrollmentChallenge(ctx)
	if ctx.status != 429 {
		t.Fatalf("status = %d, want 429", ctx.status)
	}
	response, ok := ctx.jsonPayload.(ManagementErrorResponse)
	if !ok || response.Error.Code != "device_enrollment_rate_limited" {
		t.Fatalf("error response = %#v", ctx.jsonPayload)
	}
}

func TestDeviceEnrollmentMessageMatchesEd25519Contract(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	message := webservice.DeviceEnrollmentMessage("challenge", "nonce")
	signature := ed25519.Sign(privateKey, []byte(message))
	if !ed25519.Verify(publicKey, []byte(message), signature) {
		t.Fatal("signature should verify over the published enrollment message")
	}
	if base64.RawStdEncoding.EncodeToString(signature) == "" || time.Now().Unix() == 0 {
		t.Fatal("test sanity failure")
	}
}
