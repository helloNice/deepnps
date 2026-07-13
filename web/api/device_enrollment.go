package api

import (
	"errors"
	"net/http"
	"time"

	webservice "github.com/djylb/nps/web/service"
)

type deviceEnrollmentChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	Message     string `json:"message"`
	ExpiresAt   int64  `json:"expires_at"`
}

type deviceEnrollmentCompleteRequest struct {
	ChallengeID  string `json:"challenge_id"`
	PublicKey    string `json:"public_key"`
	Signature    string `json:"signature"`
	DeviceName   string `json:"device_name,omitempty"`
	DeviceRemark string `json:"device_remark,omitempty"`
}

type deviceEnrollmentCompleteResponse struct {
	ClientID  int    `json:"client_id"`
	VerifyKey string `json:"vkey"`
	KeyID     string `json:"key_id"`
	Created   bool   `json:"created"`
}

func (a *App) DeviceEnrollmentChallenge(c Context) {
	challenge, err := a.deviceEnrollment().CreateChallenge(webservice.DeviceEnrollmentChallengeInput{
		RemoteAddr: c.ClientIP(),
	})
	if err != nil {
		respondDeviceEnrollmentError(c, err)
		return
	}
	respondManagementData(c, http.StatusOK, deviceEnrollmentChallengeResponse{
		ChallengeID: challenge.ID,
		Nonce:       challenge.Nonce,
		Message:     challenge.Message,
		ExpiresAt:   challenge.ExpiresAt,
	}, managementResponseMeta(c, time.Now().Unix(), a.runtimeIdentity().ConfigEpoch()))
}

func (a *App) DeviceEnrollmentComplete(c Context) {
	var body deviceEnrollmentCompleteRequest
	if !decodeCanonicalJSONObject(c, &body) {
		return
	}
	result, err := a.deviceEnrollment().Complete(webservice.DeviceEnrollmentCompleteInput{
		RemoteAddr:   c.ClientIP(),
		ChallengeID:  body.ChallengeID,
		PublicKey:    body.PublicKey,
		Signature:    body.Signature,
		DeviceName:   body.DeviceName,
		DeviceRemark: body.DeviceRemark,
	})
	if err != nil {
		respondDeviceEnrollmentError(c, err)
		return
	}
	respondManagementData(c, http.StatusOK, deviceEnrollmentCompleteResponse{
		ClientID:  result.ClientID,
		VerifyKey: result.VerifyKey,
		KeyID:     result.KeyID,
		Created:   result.Created,
	}, managementResponseMeta(c, time.Now().Unix(), a.runtimeIdentity().ConfigEpoch()))
}

func respondDeviceEnrollmentError(c Context, err error) {
	switch {
	case errors.Is(err, webservice.ErrDeviceEnrollmentDisabled):
		respondManagementError(c, http.StatusNotFound, err)
	case errors.Is(err, webservice.ErrDeviceEnrollmentRateLimited):
		respondManagementError(c, http.StatusTooManyRequests, err)
	case errors.Is(err, webservice.ErrDeviceChallengeNotFound),
		errors.Is(err, webservice.ErrDeviceChallengeExpired),
		errors.Is(err, webservice.ErrDeviceChallengeAlreadyUsed),
		errors.Is(err, webservice.ErrDevicePublicKeyRequired),
		errors.Is(err, webservice.ErrDevicePublicKeyInvalid),
		errors.Is(err, webservice.ErrDeviceSignatureInvalid):
		respondManagementError(c, http.StatusBadRequest, err)
	default:
		respondManagementError(c, http.StatusInternalServerError, err)
	}
}
