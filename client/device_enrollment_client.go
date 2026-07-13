package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const defaultDeviceEnrollmentHTTPTimeout = 15 * time.Second

type DeviceEnrollmentClient struct {
	Endpoint   string
	HTTPClient *http.Client
}

type DeviceEnrollmentClientOptions struct {
	Endpoint   string
	HTTPClient *http.Client
}

type DeviceEnrollmentResult struct {
	ClientID  int
	VerifyKey string
	KeyID     string
	Created   bool
}

type deviceEnrollmentChallengePayload struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	Message     string `json:"message"`
	ExpiresAt   int64  `json:"expires_at"`
}

type deviceEnrollmentCompletePayload struct {
	ClientID  int    `json:"client_id"`
	VerifyKey string `json:"vkey"`
	KeyID     string `json:"key_id"`
	Created   bool   `json:"created"`
}

type deviceEnrollmentEnvelope struct {
	Data  json.RawMessage `json:"data"`
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func NewDeviceEnrollmentClient(options DeviceEnrollmentClientOptions) *DeviceEnrollmentClient {
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultDeviceEnrollmentHTTPTimeout}
	}
	return &DeviceEnrollmentClient{
		Endpoint:   strings.TrimRight(strings.TrimSpace(options.Endpoint), "/"),
		HTTPClient: httpClient,
	}
}

func (c *DeviceEnrollmentClient) Enroll(ctx context.Context, identity *DeviceIdentity, deviceName, deviceRemark string) (DeviceEnrollmentResult, error) {
	if identity == nil {
		return DeviceEnrollmentResult{}, ErrDeviceIdentityMissingPrivateKey
	}
	challenge, err := c.createChallenge(ctx)
	if err != nil {
		return DeviceEnrollmentResult{}, err
	}
	signature, err := identity.Sign(challenge.Message)
	if err != nil {
		return DeviceEnrollmentResult{}, err
	}
	completeBody := map[string]string{
		"challenge_id": challenge.ChallengeID,
		"public_key":   identity.PublicKeyBase64(),
		"signature":    signature,
	}
	if strings.TrimSpace(deviceName) != "" {
		completeBody["device_name"] = strings.TrimSpace(deviceName)
	}
	if strings.TrimSpace(deviceRemark) != "" {
		completeBody["device_remark"] = strings.TrimSpace(deviceRemark)
	}
	var complete deviceEnrollmentCompletePayload
	if err := c.postJSON(ctx, "/api/devices/enrollment/complete", completeBody, &complete); err != nil {
		return DeviceEnrollmentResult{}, err
	}
	if strings.TrimSpace(complete.VerifyKey) == "" {
		return DeviceEnrollmentResult{}, fmt.Errorf("device enrollment response missing vkey")
	}
	return DeviceEnrollmentResult{
		ClientID:  complete.ClientID,
		VerifyKey: complete.VerifyKey,
		KeyID:     complete.KeyID,
		Created:   complete.Created,
	}, nil
}

func (c *DeviceEnrollmentClient) createChallenge(ctx context.Context) (deviceEnrollmentChallengePayload, error) {
	var challenge deviceEnrollmentChallengePayload
	if err := c.postJSON(ctx, "/api/devices/enrollment/challenge", map[string]string{}, &challenge); err != nil {
		return deviceEnrollmentChallengePayload{}, err
	}
	if strings.TrimSpace(challenge.ChallengeID) == "" || strings.TrimSpace(challenge.Message) == "" {
		return deviceEnrollmentChallengePayload{}, fmt.Errorf("device enrollment challenge response is incomplete")
	}
	return challenge, nil
}

func (c *DeviceEnrollmentClient) postJSON(ctx context.Context, endpointPath string, body interface{}, out interface{}) error {
	if c == nil || strings.TrimSpace(c.Endpoint) == "" {
		return fmt.Errorf("device enrollment endpoint is empty")
	}
	target, err := c.url(endpointPath)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "deepnps-zero-touch/1")
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultDeviceEnrollmentHTTPTimeout}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var envelope deviceEnrollmentEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("decode device enrollment response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if envelope.Error.Message != "" {
			return fmt.Errorf("device enrollment failed: %s", envelope.Error.Message)
		}
		return fmt.Errorf("device enrollment failed: status %s", resp.Status)
	}
	if len(envelope.Data) == 0 {
		return fmt.Errorf("device enrollment response missing data")
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return fmt.Errorf("decode device enrollment data: %w", err)
	}
	return nil
}

func (c *DeviceEnrollmentClient) url(endpointPath string) (string, error) {
	base, err := url.Parse(c.Endpoint)
	if err != nil {
		return "", err
	}
	if base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("device enrollment endpoint must include scheme and host")
	}
	base.Path = path.Join(strings.TrimRight(base.Path, "/"), endpointPath)
	return base.String(), nil
}
