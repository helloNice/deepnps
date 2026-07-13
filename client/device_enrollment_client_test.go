package client

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeviceEnrollmentClientEnrollsWithSignedChallenge(t *testing.T) {
	store := NewDeviceIdentityStore(DeviceIdentityStoreOptions{RootDir: t.TempDir()})
	identity, _, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}
	var completeBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/devices/enrollment/challenge":
			if r.Method != http.MethodPost {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"challenge_id": "challenge-1",
					"nonce":        "nonce-1",
					"message":      "deepnps-device-enrollment\nchallenge-1\nnonce-1",
					"expires_at":   123,
				},
				"meta": map[string]interface{}{},
			})
		case "/api/devices/enrollment/complete":
			if err := json.NewDecoder(r.Body).Decode(&completeBody); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"client_id": 9,
					"vkey":      "enrolled-vkey",
					"key_id":    "kid",
					"created":   true,
				},
				"meta": map[string]interface{}{},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := NewDeviceEnrollmentClient(DeviceEnrollmentClientOptions{Endpoint: server.URL}).Enroll(t.Context(), identity, "pc", "remark")
	if err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}
	if result.ClientID != 9 || result.VerifyKey != "enrolled-vkey" || result.KeyID != "kid" || !result.Created {
		t.Fatalf("Enroll() result = %+v", result)
	}
	if completeBody["challenge_id"] != "challenge-1" || completeBody["public_key"] != identity.PublicKeyBase64() || completeBody["signature"] == "" || completeBody["device_name"] != "pc" || completeBody["device_remark"] != "remark" {
		t.Fatalf("complete body = %#v", completeBody)
	}
	publicKey, err := decodeDeviceBytes(completeBody["public_key"])
	if err != nil {
		t.Fatalf("decode public key error = %v", err)
	}
	signature, err := decodeDeviceBytes(completeBody["signature"])
	if err != nil {
		t.Fatalf("decode signature error = %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte("deepnps-device-enrollment\nchallenge-1\nnonce-1"), signature) {
		t.Fatal("complete signature does not verify")
	}
}

func TestDeviceEnrollmentClientReturnsServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{"message": "disabled"},
		})
	}))
	defer server.Close()
	store := NewDeviceIdentityStore(DeviceIdentityStoreOptions{RootDir: t.TempDir()})
	identity, _, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}
	if _, err := NewDeviceEnrollmentClient(DeviceEnrollmentClientOptions{Endpoint: server.URL}).Enroll(t.Context(), identity, "", ""); err == nil {
		t.Fatal("Enroll() error = nil, want server error")
	}
}
