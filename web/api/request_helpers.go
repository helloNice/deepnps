package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	webservice "github.com/djylb/nps/web/service"
)

type Handler func(Context)

type SessionEditor interface {
	Set(string, interface{})
	Delete(string)
}

type Context interface {
	BaseContext() context.Context
	String(string) string
	LookupString(string) (string, bool)
	Int(string, ...int) int
	Bool(string, ...bool) bool
	Method() string
	Host() string
	RemoteAddr() string
	ClientIP() string
	RequestHeader(string) string
	SessionValue(string) interface{}
	SetSessionValue(string, interface{})
	DeleteSessionValue(string)
	SetParam(string, string)
	RespondJSON(int, interface{})
	RespondString(int, string)
	RespondData(int, string, []byte)
	Redirect(int, string)
	SetResponseHeader(string, string)
	IsWritten() bool
	Actor() *Actor
	SetActor(*Actor)
	Metadata() RequestMetadata
}

type rawBodyContext interface {
	RawBody() []byte
}

type rawBodyViewContext interface {
	RawBodyView() []byte
}

var nonAlphaNumericFieldPattern = regexp.MustCompile(`[^a-z0-9]+`)

type ManagementPagination struct {
	Offset   int  `json:"offset"`
	Limit    int  `json:"limit"`
	Returned int  `json:"returned"`
	Total    int  `json:"total"`
	HasMore  bool `json:"has_more"`
}

type ManagementResponseMeta struct {
	RequestID   string                `json:"request_id,omitempty"`
	GeneratedAt int64                 `json:"generated_at,omitempty"`
	ConfigEpoch string                `json:"config_epoch,omitempty"`
	Pagination  *ManagementPagination `json:"pagination,omitempty"`
}

type ManagementDataResponse struct {
	Data any                    `json:"data,omitempty"`
	Meta ManagementResponseMeta `json:"meta"`
}

type ManagementErrorDetail struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

type ManagementErrorResponse struct {
	Error ManagementErrorDetail `json:"error"`
}

func requestRawBody(c Context) []byte {
	if c == nil {
		return nil
	}
	if provider, ok := c.(rawBodyViewContext); ok && provider != nil {
		return provider.RawBodyView()
	}
	provider, ok := c.(rawBodyContext)
	if !ok || provider == nil {
		return nil
	}
	return provider.RawBody()
}

func requestString(c Context, key string) string {
	return c.String(key)
}

func requestIntValue(c Context, key string, def ...int) int {
	return c.Int(key, def...)
}

func requestBoolValue(c Context, key string, def ...bool) bool {
	return c.Bool(key, def...)
}

func decodeCanonicalJSONObject(c Context, dest interface{}) bool {
	raw := bytes.TrimSpace(requestRawBody(c))
	if len(raw) == 0 {
		respondManagementErrorMessage(c, http.StatusBadRequest, "json_body_required", "json body is required", nil)
		return false
	}
	return decodeJSONBodyObject(raw, c, dest)
}

func decodeOptionalCanonicalJSONObject(c Context, dest interface{}) bool {
	raw := bytes.TrimSpace(requestRawBody(c))
	if len(raw) == 0 {
		return true
	}
	return decodeJSONBodyObject(raw, c, dest)
}

func decodeJSONBodyObject(raw []byte, c Context, dest interface{}) bool {
	if raw[0] != '{' {
		respondManagementErrorMessage(c, http.StatusBadRequest, "invalid_json_body", "json object body is required", nil)
		return false
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		respondManagementErrorMessage(c, http.StatusBadRequest, "invalid_json_body", "invalid json body", map[string]any{
			"detail": strings.TrimSpace(err.Error()),
		})
		return false
	}
	if err := ensureJSONEOF(decoder); err != nil {
		respondManagementErrorMessage(c, http.StatusBadRequest, "invalid_json_body", "invalid json body", map[string]any{
			"detail": strings.TrimSpace(err.Error()),
		})
		return false
	}
	return true
}

func ensureJSONEOF(decoder *json.Decoder) error {
	if decoder == nil {
		return nil
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return errors.New("json body must contain a single object")
}

func respondMissingRequestField(c Context, field string) {
	field = strings.TrimSpace(field)
	if field == "" {
		respondManagementErrorMessage(c, http.StatusBadRequest, "field_required", "missing field", nil)
		return
	}
	code := strings.ToLower(field)
	code = nonAlphaNumericFieldPattern.ReplaceAllString(code, "_")
	code = strings.Trim(code, "_")
	if code == "" {
		code = "field"
	}
	respondManagementErrorMessage(c, http.StatusBadRequest, code+"_required", "missing "+field, nil)
}

func managementResponseMeta(c Context, generatedAt int64, configEpoch string) ManagementResponseMeta {
	meta := ManagementResponseMeta{
		GeneratedAt: generatedAt,
		ConfigEpoch: strings.TrimSpace(configEpoch),
	}
	if c != nil {
		meta.RequestID = strings.TrimSpace(c.Metadata().RequestID)
	}
	return meta
}

func ManagementResponseMetaForRequest(metadata RequestMetadata, generatedAt int64, configEpoch string) ManagementResponseMeta {
	return ManagementResponseMeta{
		RequestID:   strings.TrimSpace(metadata.RequestID),
		GeneratedAt: generatedAt,
		ConfigEpoch: strings.TrimSpace(configEpoch),
	}
}

func respondManagementData(c Context, status int, data any, meta ManagementResponseMeta) {
	c.RespondJSON(status, ManagementDataResponse{
		Data: data,
		Meta: meta,
	})
}

func RespondManagementData(c Context, status int, data any, meta ManagementResponseMeta) {
	respondManagementData(c, status, data, meta)
}

func respondManagementError(c Context, status int, err error) {
	c.RespondJSON(status, managementErrorResponse(status, err))
}

func RespondManagementError(c Context, status int, err error) {
	respondManagementError(c, status, err)
}

func respondManagementErrorMessage(c Context, status int, code, message string, details map[string]any) {
	code = strings.TrimSpace(code)
	if code == "" {
		code = "request_failed"
	}
	message = strings.TrimSpace(message)
	if message == "" {
		message = http.StatusText(status)
	}
	c.RespondJSON(status, ManagementErrorResponse{
		Error: ManagementErrorDetail{
			Code:    code,
			Message: message,
			Details: details,
		},
	})
}

func RespondManagementErrorMessage(c Context, status int, code, message string, details map[string]any) {
	respondManagementErrorMessage(c, status, code, message, details)
}

func managementErrorResponse(status int, err error) ManagementErrorResponse {
	detail := ManagementErrorDetail{
		Code:    managementErrorCode(err),
		Message: managementErrorMessage(err, status),
	}
	return ManagementErrorResponse{Error: detail}
}

func ManagementErrorResponseForStatus(status int, err error) ManagementErrorResponse {
	return managementErrorResponse(status, err)
}

func managementErrorCode(err error) string {
	switch {
	case err == nil:
		return "request_failed"
	case errors.Is(err, webservice.ErrUnauthenticated):
		return "unauthorized"
	case errors.Is(err, webservice.ErrForbidden):
		return "forbidden"
	case errors.Is(err, webservice.ErrUserNotFound):
		return "user_not_found"
	case errors.Is(err, webservice.ErrClientNotFound):
		return "client_not_found"
	case errors.Is(err, webservice.ErrTunnelNotFound):
		return "tunnel_not_found"
	case errors.Is(err, webservice.ErrHostNotFound):
		return "host_not_found"
	case errors.Is(err, webservice.ErrSnapshotExportUnsupported):
		return "config_export_unsupported"
	case errors.Is(err, webservice.ErrManagementPlatformNotFound):
		return "management_platform_not_found"
	case errors.Is(err, webservice.ErrInvalidCallbackQueueAction):
		return "invalid_callback_queue_action"
	case errors.Is(err, webservice.ErrClientIdentifierRequired):
		return "client_identifier_required"
	case errors.Is(err, webservice.ErrClientIdentifierConflict):
		return "client_identifier_conflict"
	case errors.Is(err, webservice.ErrInvalidTrafficItems):
		return "invalid_traffic_items"
	case errors.Is(err, webservice.ErrTrafficItemsEmpty):
		return "traffic_items_empty"
	case errors.Is(err, webservice.ErrTrafficClientRequired):
		return "traffic_client_required"
	case errors.Is(err, webservice.ErrTrafficTargetRequired):
		return "traffic_target_required"
	case errors.Is(err, webservice.ErrClientVKeyDuplicate):
		return "client_verify_key_duplicate"
	case errors.Is(err, webservice.ErrClientLimitExceeded):
		return "client_limit_exceeded"
	case errors.Is(err, webservice.ErrClientRateLimitExceeded):
		return "client_rate_limit_exceeded"
	case errors.Is(err, webservice.ErrClientConnLimitExceeded):
		return "client_connection_limit_exceeded"
	case errors.Is(err, webservice.ErrRevisionConflict):
		return "revision_conflict"
	case errors.Is(err, webservice.ErrHostExists):
		return "host_already_exists"
	case errors.Is(err, webservice.ErrPortUnavailable):
		return "port_unavailable"
	case errors.Is(err, webservice.ErrTunnelLimitExceeded):
		return "tunnel_limit_exceeded"
	case errors.Is(err, webservice.ErrHostLimitExceeded):
		return "host_limit_exceeded"
	case errors.Is(err, webservice.ErrClientResourceLimitExceeded):
		return "client_resource_limit_exceeded"
	case errors.Is(err, webservice.ErrReservedUsername):
		return "reserved_username"
	case errors.Is(err, webservice.ErrUserUsernameRequired):
		return "username_required"
	case errors.Is(err, webservice.ErrUserPasswordRequired):
		return "password_required"
	case errors.Is(err, webservice.ErrInvalidTOTPSecret):
		return "invalid_totp_secret"
	case errors.Is(err, webservice.ErrClientModifyFailed):
		return "client_modify_failed"
	case errors.Is(err, webservice.ErrModeRequired):
		return "mode_required"
	case errors.Is(err, webservice.ErrDeviceEnrollmentDisabled):
		return "device_enrollment_disabled"
	case errors.Is(err, webservice.ErrDeviceEnrollmentRateLimited):
		return "device_enrollment_rate_limited"
	case errors.Is(err, webservice.ErrDeviceChallengeNotFound):
		return "device_challenge_not_found"
	case errors.Is(err, webservice.ErrDeviceChallengeExpired):
		return "device_challenge_expired"
	case errors.Is(err, webservice.ErrDevicePublicKeyRequired):
		return "device_public_key_required"
	case errors.Is(err, webservice.ErrDevicePublicKeyInvalid):
		return "device_public_key_invalid"
	case errors.Is(err, webservice.ErrDeviceSignatureInvalid):
		return "device_signature_invalid"
	case errors.Is(err, webservice.ErrDeviceChallengeAlreadyUsed):
		return "device_challenge_already_used"
	case errors.Is(err, webservice.ErrDeviceEnrollmentCreateFailed):
		return "device_enrollment_create_failed"
	default:
		return "request_failed"
	}
}

func managementErrorMessage(err error, status int) string {
	if err != nil {
		return strings.TrimSpace(err.Error())
	}
	if statusText := strings.TrimSpace(http.StatusText(status)); statusText != "" {
		return strings.ToLower(statusText)
	}
	return "request failed"
}

// StringifyRequestValue normalizes decoded JSON values into the string form used
// by request param helpers and WS/body path materialization.
func StringifyRequestValue(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case json.Number:
		return typed.String()
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	case []interface{}, map[string]interface{}:
		raw, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(raw)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}
