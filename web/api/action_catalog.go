package api

import (
	"net/http"
	"strings"
	"sync"

	"github.com/djylb/nps/lib/servercfg"
	webservice "github.com/djylb/nps/web/service"
)

type ActionOwnership string

const (
	ActionOwnershipNone   ActionOwnership = ""
	ActionOwnershipClient ActionOwnership = "client"
	ActionOwnershipTunnel ActionOwnership = "tunnel"
	ActionOwnershipHost   ActionOwnership = "host"
)

type ActionSpec struct {
	Resource         string
	Action           string
	Method           string
	Path             string
	Permission       string
	ClientScope      bool
	Ownership        ActionOwnership
	Protected        bool
	RequiredFeatures []RequiredFeature
	Visible          func(cfg *servercfg.Snapshot, actor *Actor, authz webservice.AuthorizationService) bool
	Handler          Handler
}

type ActionEntry struct {
	Resource         string            `json:"resource"`
	Action           string            `json:"action"`
	Method           string            `json:"method"`
	Path             string            `json:"path,omitempty"`
	Permission       string            `json:"permission,omitempty"`
	ClientScope      bool              `json:"client_scope"`
	Ownership        ActionOwnership   `json:"ownership,omitempty"`
	Protected        bool              `json:"protected"`
	RequiredFeatures []RequiredFeature `json:"required_features,omitempty"`
}

type RequiredFeature string

const (
	RequiredFeatureAllowUserRegister RequiredFeature = "allow_user_register"
	RequiredFeatureDeviceEnrollment  RequiredFeature = "allow_device_enrollment"
)

var (
	protectedActionSpecsOnce sync.Once
	protectedActionSpecs     map[string]ActionSpec
)

func SessionActionCatalog(app *App) []ActionSpec {
	if app == nil {
		app = &App{}
	}
	return []ActionSpec{
		{Resource: "system", Action: "health", Method: http.MethodGet, Path: "/api/system/health", Handler: app.ManagementHealth},
		{Resource: "session", Action: "read", Method: http.MethodGet, Path: "/api/auth/session", Handler: app.SessionStatus},
		{Resource: "session", Action: "create", Method: http.MethodPost, Path: "/api/auth/session", Handler: app.CreateSession},
		{Resource: "auth", Action: "token", Method: http.MethodPost, Path: "/api/auth/token", Handler: app.Token},
		{
			Resource: "auth", Action: "register", Method: http.MethodPost, Path: "/api/auth/register",
			RequiredFeatures: []RequiredFeature{RequiredFeatureAllowUserRegister}, Handler: app.RegisterAuthUser,
		},
		{Resource: "session", Action: "logout", Method: http.MethodPost, Path: "/api/auth/session/logout", Handler: app.SessionLogout},
		{Resource: "access", Action: "ip_limit_register", Method: http.MethodPost, Path: "/api/access/ip-limit/actions/register", Handler: app.RegisterIPLimitAccess},
		{
			Resource: "devices", Action: "enrollment_challenge", Method: http.MethodPost, Path: "/api/devices/enrollment/challenge",
			RequiredFeatures: []RequiredFeature{RequiredFeatureDeviceEnrollment}, Handler: app.DeviceEnrollmentChallenge,
		},
		{
			Resource: "devices", Action: "enrollment_complete", Method: http.MethodPost, Path: "/api/devices/enrollment/complete",
			RequiredFeatures: []RequiredFeature{RequiredFeatureDeviceEnrollment}, Handler: app.DeviceEnrollmentComplete,
		},
	}
}

func ProtectedActionCatalog(app *App) []ActionSpec {
	if app == nil {
		app = &App{}
	}
	return []ActionSpec{
		{Resource: "system", Action: "overview", Method: http.MethodGet, Path: "/api/system/overview", Protected: true, Visible: nodeActionVisibleByScope(func(scope webservice.NodeAccessScope) bool { return scope.CanViewStatus() || scope.CanViewUsage() }), Handler: app.NodeOverview},
		{Resource: "system", Action: "dashboard", Method: http.MethodGet, Path: "/api/system/dashboard", Protected: true, Visible: nodeActionVisibleByScope(func(scope webservice.NodeAccessScope) bool { return scope.IsFullAccess() }), Handler: app.NodeDashboard},
		{Resource: "system", Action: "registration", Method: http.MethodGet, Path: "/api/system/registration", Protected: true, Visible: nodeActionVisibleByScope(func(scope webservice.NodeAccessScope) bool { return scope.CanViewStatus() }), Handler: app.NodeRegistration},
		{Resource: "system", Action: "operations", Method: http.MethodGet, Path: "/api/system/operations", Protected: true, Visible: nodeActionVisibleByScope(func(scope webservice.NodeAccessScope) bool { return scope.CanViewStatus() }), Handler: app.NodeOperations},
		{Resource: "system", Action: "status", Method: http.MethodGet, Path: "/api/system/status", Protected: true, Visible: nodeActionVisibleByScope(func(scope webservice.NodeAccessScope) bool { return scope.CanViewStatus() }), Handler: app.NodeStatus},
		{Resource: "system", Action: "changes", Method: http.MethodGet, Path: "/api/system/changes", Protected: true},
		{Resource: "system", Action: "usage_snapshot", Method: http.MethodGet, Path: "/api/system/usage-snapshot", Protected: true, Visible: nodeActionVisibleByScope(func(scope webservice.NodeAccessScope) bool { return scope.CanViewUsage() }), Handler: app.NodeUsageSnapshot},
		{Resource: "system", Action: "export", Method: http.MethodGet, Path: "/api/system/export", Protected: true, Visible: nodeActionVisibleByScope(func(scope webservice.NodeAccessScope) bool { return scope.CanExportConfig() }), Handler: app.NodeConfig},
		{Resource: "system", Action: "import", Method: http.MethodPost, Path: "/api/system/import", Protected: true, Visible: nodeActionVisibleByScope(func(scope webservice.NodeAccessScope) bool { return scope.CanExportConfig() })},
		{Resource: "system", Action: "sync", Method: http.MethodPost, Path: "/api/system/actions/sync", Protected: true, Visible: nodeActionVisibleByScope(func(scope webservice.NodeAccessScope) bool { return scope.CanSync() }), Handler: app.NodeSync},
		{Resource: "traffic", Action: "write", Method: http.MethodPost, Path: "/api/traffic", Protected: true, Visible: nodeActionVisibleByScope(func(scope webservice.NodeAccessScope) bool { return scope.CanWriteTraffic() }), Handler: app.NodeTraffic},
		{Resource: "tunnels", Action: "list", Method: http.MethodGet, Path: "/api/tunnels", Permission: webservice.PermissionTunnelsRead, ClientScope: true, Protected: true, Handler: app.NodeTunnels},
		{Resource: "tunnels", Action: "create", Method: http.MethodPost, Path: "/api/tunnels", Permission: webservice.PermissionTunnelsCreate, ClientScope: true, Protected: true, Handler: app.NodeCreateTunnel},
		{Resource: "hosts", Action: "list", Method: http.MethodGet, Path: "/api/hosts", Permission: webservice.PermissionHostsRead, ClientScope: true, Protected: true, Handler: app.NodeHosts},
		{Resource: "hosts", Action: "create", Method: http.MethodPost, Path: "/api/hosts", Permission: webservice.PermissionHostsCreate, ClientScope: true, Protected: true, Handler: app.NodeCreateHost},
		{Resource: "tunnels", Action: "read", Method: http.MethodGet, Path: "/api/tunnels/{id}", Permission: webservice.PermissionTunnelsRead, Ownership: ActionOwnershipTunnel, Protected: true, Handler: app.NodeTunnel},
		{Resource: "tunnels", Action: "update", Method: http.MethodPost, Path: "/api/tunnels/{id}/actions/update", Permission: webservice.PermissionTunnelsUpdate, Ownership: ActionOwnershipTunnel, Protected: true, Handler: app.NodeUpdateTunnel},
		{Resource: "tunnels", Action: "start", Method: http.MethodPost, Path: "/api/tunnels/{id}/actions/start", Permission: webservice.PermissionTunnelsControl, Ownership: ActionOwnershipTunnel, Protected: true, Handler: app.NodeStartTunnel},
		{Resource: "tunnels", Action: "stop", Method: http.MethodPost, Path: "/api/tunnels/{id}/actions/stop", Permission: webservice.PermissionTunnelsControl, Ownership: ActionOwnershipTunnel, Protected: true, Handler: app.NodeStopTunnel},
		{Resource: "tunnels", Action: "clear", Method: http.MethodPost, Path: "/api/tunnels/{id}/actions/clear", Permission: webservice.PermissionTunnelsControl, Ownership: ActionOwnershipTunnel, Protected: true, Handler: app.NodeClearTunnel},
		{Resource: "tunnels", Action: "delete", Method: http.MethodPost, Path: "/api/tunnels/{id}/actions/delete", Permission: webservice.PermissionTunnelsDelete, Ownership: ActionOwnershipTunnel, Protected: true, Handler: app.NodeDeleteTunnel},
		{Resource: "hosts", Action: "read", Method: http.MethodGet, Path: "/api/hosts/{id}", Permission: webservice.PermissionHostsRead, Ownership: ActionOwnershipHost, Protected: true, Handler: app.NodeHost},
		{Resource: "hosts", Action: "cert_suggestion", Method: http.MethodGet, Path: "/api/hosts/cert-suggestion", Permission: webservice.PermissionHostsRead, Protected: true, Handler: app.NodeHostCertSuggestion},
		{Resource: "hosts", Action: "update", Method: http.MethodPost, Path: "/api/hosts/{id}/actions/update", Permission: webservice.PermissionHostsUpdate, Ownership: ActionOwnershipHost, Protected: true, Handler: app.NodeUpdateHost},
		{Resource: "hosts", Action: "start", Method: http.MethodPost, Path: "/api/hosts/{id}/actions/start", Permission: webservice.PermissionHostsControl, Ownership: ActionOwnershipHost, Protected: true, Handler: app.NodeStartHost},
		{Resource: "hosts", Action: "stop", Method: http.MethodPost, Path: "/api/hosts/{id}/actions/stop", Permission: webservice.PermissionHostsControl, Ownership: ActionOwnershipHost, Protected: true, Handler: app.NodeStopHost},
		{Resource: "hosts", Action: "clear", Method: http.MethodPost, Path: "/api/hosts/{id}/actions/clear", Permission: webservice.PermissionHostsControl, Ownership: ActionOwnershipHost, Protected: true, Handler: app.NodeClearHost},
		{Resource: "hosts", Action: "delete", Method: http.MethodPost, Path: "/api/hosts/{id}/actions/delete", Permission: webservice.PermissionHostsDelete, Ownership: ActionOwnershipHost, Protected: true, Handler: app.NodeDeleteHost},
		{Resource: "clients", Action: "list", Method: http.MethodGet, Path: "/api/clients", Permission: webservice.PermissionClientsRead, Protected: true, Handler: app.NodeClients},
		{Resource: "clients", Action: "qrcode", Method: http.MethodGet, Path: "/api/tools/qrcode", Permission: webservice.PermissionClientsRead, Protected: true, Handler: app.NodeClientQRCode},
		{Resource: "clients", Action: "qrcode_generate", Method: http.MethodPost, Path: "/api/tools/qrcode", Permission: webservice.PermissionClientsRead, Protected: true, Handler: app.NodeClientQRCode},
		{Resource: "clients", Action: "create", Method: http.MethodPost, Path: "/api/clients", Permission: webservice.PermissionClientsCreate, Protected: true, Handler: app.NodeCreateClient},
		{Resource: "clients", Action: "connections", Method: http.MethodGet, Path: "/api/clients/{id}/connections", Permission: webservice.PermissionClientsRead, Ownership: ActionOwnershipClient, Protected: true, Handler: app.NodeClientConnections},
		{Resource: "clients", Action: "clear_all", Method: http.MethodPost, Path: "/api/clients/actions/clear", Permission: webservice.PermissionClientsStatus, Protected: true, Handler: app.NodeClearClients},
		{Resource: "clients", Action: "kick", Method: http.MethodPost, Path: "/api/clients/actions/kick", Permission: webservice.PermissionClientsStatus, Protected: true, Handler: app.NodeKick},
		{Resource: "clients", Action: "ping", Method: http.MethodPost, Path: "/api/clients/{id}/actions/ping", Permission: webservice.PermissionClientsRead, Ownership: ActionOwnershipClient, Protected: true, Handler: app.NodePingClient},
		{Resource: "clients", Action: "read", Method: http.MethodGet, Path: "/api/clients/{id}", Permission: webservice.PermissionClientsRead, Ownership: ActionOwnershipClient, Protected: true, Handler: app.NodeClient},
		{Resource: "clients", Action: "update", Method: http.MethodPost, Path: "/api/clients/{id}/actions/update", Permission: webservice.PermissionClientsUpdate, Ownership: ActionOwnershipClient, Protected: true, Handler: app.NodeUpdateClient},
		{Resource: "clients", Action: "clear", Method: http.MethodPost, Path: "/api/clients/{id}/actions/clear", Permission: webservice.PermissionClientsStatus, Ownership: ActionOwnershipClient, Protected: true, Handler: app.NodeClearClient},
		{Resource: "clients", Action: "status", Method: http.MethodPost, Path: "/api/clients/{id}/actions/status", Permission: webservice.PermissionClientsStatus, Ownership: ActionOwnershipClient, Protected: true, Handler: app.NodeSetClientStatus},
		{Resource: "clients", Action: "delete", Method: http.MethodPost, Path: "/api/clients/{id}/actions/delete", Permission: webservice.PermissionClientsDelete, Ownership: ActionOwnershipClient, Protected: true, Handler: app.NodeDeleteClient},
		{Resource: "users", Action: "list", Method: http.MethodGet, Path: "/api/users", Permission: webservice.PermissionManagementAdmin, Protected: true, Handler: app.NodeUsers},
		{Resource: "users", Action: "read", Method: http.MethodGet, Path: "/api/users/{id}", Permission: webservice.PermissionManagementAdmin, Protected: true, Handler: app.NodeUser},
		{Resource: "users", Action: "create", Method: http.MethodPost, Path: "/api/users", Permission: webservice.PermissionManagementAdmin, Protected: true, Handler: app.NodeCreateUser},
		{Resource: "users", Action: "update", Method: http.MethodPost, Path: "/api/users/{id}/actions/update", Permission: webservice.PermissionManagementAdmin, Protected: true, Handler: app.NodeUpdateUser},
		{Resource: "users", Action: "status", Method: http.MethodPost, Path: "/api/users/{id}/actions/status", Permission: webservice.PermissionManagementAdmin, Protected: true, Handler: app.NodeSetUserStatus},
		{Resource: "users", Action: "delete", Method: http.MethodPost, Path: "/api/users/{id}/actions/delete", Permission: webservice.PermissionManagementAdmin, Protected: true, Handler: app.NodeDeleteUser},
		{Resource: "settings_global", Action: "read", Method: http.MethodGet, Path: "/api/settings/global", Permission: webservice.PermissionGlobalManage, Protected: true, Handler: app.NodeGlobal},
		{Resource: "settings_global", Action: "update", Method: http.MethodPost, Path: "/api/settings/global/actions/update", Permission: webservice.PermissionGlobalManage, Protected: true, Handler: app.NodeUpdateGlobal},
		{Resource: "security_bans", Action: "list", Method: http.MethodGet, Path: "/api/security/bans", Permission: webservice.PermissionGlobalManage, Protected: true, Handler: app.NodeBanList},
		{Resource: "security_bans", Action: "delete", Method: http.MethodPost, Path: "/api/security/bans/actions/delete", Permission: webservice.PermissionGlobalManage, Protected: true, Handler: app.NodeUnban},
		{Resource: "security_bans", Action: "delete_all", Method: http.MethodPost, Path: "/api/security/bans/actions/delete_all", Permission: webservice.PermissionGlobalManage, Protected: true, Handler: app.NodeUnbanAll},
		{Resource: "security_bans", Action: "clean", Method: http.MethodPost, Path: "/api/security/bans/actions/clean", Permission: webservice.PermissionGlobalManage, Protected: true, Handler: app.NodeBanClean},
		{Resource: "callbacks_queue", Action: "list", Method: http.MethodGet, Path: "/api/callbacks/queue", Protected: true, Visible: nodeActionVisibleCallbackQueue(func(scope webservice.NodeAccessScope) bool { return scope.CanViewCallbackQueue() })},
		{Resource: "callbacks_queue", Action: "replay", Method: http.MethodPost, Path: "/api/callbacks/queue/actions/replay", Protected: true, Visible: nodeActionVisibleCallbackQueue(func(scope webservice.NodeAccessScope) bool { return scope.CanManageCallbackQueue() })},
		{Resource: "callbacks_queue", Action: "clear", Method: http.MethodPost, Path: "/api/callbacks/queue/actions/clear", Protected: true, Visible: nodeActionVisibleCallbackQueue(func(scope webservice.NodeAccessScope) bool { return scope.CanManageCallbackQueue() })},
		{Resource: "webhooks", Action: "list", Method: http.MethodGet, Path: "/api/webhooks", Protected: true, Visible: nodeActionVisibleWebhookManageable},
		{Resource: "webhooks", Action: "read", Method: http.MethodGet, Path: "/api/webhooks/{id}", Protected: true, Visible: nodeActionVisibleWebhookManageable},
		{Resource: "webhooks", Action: "create", Method: http.MethodPost, Path: "/api/webhooks", Protected: true, Visible: nodeActionVisibleWebhookManageable},
		{Resource: "webhooks", Action: "update", Method: http.MethodPost, Path: "/api/webhooks/{id}/actions/update", Protected: true, Visible: nodeActionVisibleWebhookManageable},
		{Resource: "webhooks", Action: "status", Method: http.MethodPost, Path: "/api/webhooks/{id}/actions/status", Protected: true, Visible: nodeActionVisibleWebhookManageable},
		{Resource: "webhooks", Action: "delete", Method: http.MethodPost, Path: "/api/webhooks/{id}/actions/delete", Protected: true, Visible: nodeActionVisibleWebhookManageable},
	}
}

func nodeActionVisibleByScope(check func(webservice.NodeAccessScope) bool) func(cfg *servercfg.Snapshot, actor *Actor, authz webservice.AuthorizationService) bool {
	return func(_ *servercfg.Snapshot, actor *Actor, authz webservice.AuthorizationService) bool {
		if check == nil {
			return true
		}
		return check(webservice.ResolveNodeAccessScopeWithAuthorization(authz, PrincipalFromActor(actor)))
	}
}

func nodeActionVisibleCallbackQueue(check func(webservice.NodeAccessScope) bool) func(cfg *servercfg.Snapshot, actor *Actor, authz webservice.AuthorizationService) bool {
	return func(cfg *servercfg.Snapshot, actor *Actor, authz webservice.AuthorizationService) bool {
		scope := webservice.ResolveNodeAccessScopeWithAuthorization(authz, PrincipalFromActor(actor))
		if check != nil && !check(scope) {
			return false
		}
		if cfg == nil {
			return false
		}
		for _, platform := range cfg.Runtime.EnabledCallbackManagementPlatforms() {
			if scope.AllowsPlatform(platform.PlatformID) {
				return true
			}
		}
		return false
	}
}

func nodeActionVisibleWebhookManageable(_ *servercfg.Snapshot, actor *Actor, _ webservice.AuthorizationService) bool {
	if actor == nil {
		return false
	}
	if actor.IsAdmin {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(actor.Kind), "platform_admin")
}

func VisibleActionEntries(cfg *servercfg.Snapshot, baseURL string, actor *Actor, authz webservice.AuthorizationService, specs []ActionSpec) []ActionEntry {
	actor, principal := normalizeActorWithAuthorization(actor, authz)
	entries := make([]ActionEntry, 0, len(specs))
	for _, spec := range specs {
		if !actionSpecEnabled(cfg, spec) {
			continue
		}
		if spec.Protected && !principal.Authenticated {
			continue
		}
		if permission := strings.TrimSpace(spec.Permission); permission != "" && !authz.Allows(principal, permission) {
			continue
		}
		if spec.Visible != nil && !spec.Visible(cfg, actor, authz) {
			continue
		}
		path, method := publishedAction(baseURL, spec)
		entries = append(entries, ActionEntry{
			Resource:         publishedActionResource(spec),
			Action:           publishedActionName(spec),
			Method:           method,
			Path:             path,
			Permission:       spec.Permission,
			ClientScope:      spec.ClientScope,
			Ownership:        spec.Ownership,
			Protected:        spec.Protected,
			RequiredFeatures: copyRequiredFeatures(spec.RequiredFeatures),
		})
	}
	return entries
}

func copyRequiredFeatures(features []RequiredFeature) []RequiredFeature {
	if len(features) == 0 {
		return nil
	}
	copied := make([]RequiredFeature, len(features))
	copy(copied, features)
	return copied
}

func publishedActionResource(spec ActionSpec) string {
	if resource := strings.ToLower(strings.TrimSpace(spec.Resource)); resource != "" {
		return resource
	}
	return ""
}

func publishedActionName(spec ActionSpec) string {
	if action := strings.ToLower(strings.TrimSpace(spec.Action)); action != "" {
		return action
	}
	return ""
}

func publishedActionPath(baseURL string, spec ActionSpec) string {
	path, _ := publishedAction(baseURL, spec)
	return path
}

func PublishedActionPathForResourceAction(baseURL, resource, action string) string {
	spec, ok := protectedActionSpec(resource, action)
	if !ok {
		return ""
	}
	return publishedActionPath(baseURL, spec)
}

func PublishedActionRequestForResourceAction(baseURL, resource, action string, params map[string]string) (string, string) {
	spec, ok := protectedActionSpec(resource, action)
	if !ok {
		return "", ""
	}
	pathTemplate, method := publishedAction(baseURL, spec)
	if pathTemplate == "" || method == "" {
		return "", ""
	}
	path := materializePublishedPath(pathTemplate, params)
	if path == "" {
		return "", ""
	}
	return path, method
}

func PublishedActionMethodForResourceAction(resource, action string) string {
	spec, ok := protectedActionSpec(resource, action)
	if !ok {
		return ""
	}
	return publishedActionMethod(spec)
}

func HasPublishedActionForResourceAction(resource, action string) bool {
	spec, ok := protectedActionSpec(resource, action)
	if !ok {
		return false
	}
	path, method := publishedAction("", spec)
	return path != "" && method != ""
}

func publishedActionMethod(spec ActionSpec) string {
	_, method := publishedAction("", spec)
	return method
}

func publishedAction(baseURL string, spec ActionSpec) (string, string) {
	path := joinBase(baseURL, spec.Path)
	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if path == "" || method == "" {
		return "", ""
	}
	return path, method
}

func protectedActionSpec(resource, action string) (ActionSpec, bool) {
	key := protectedActionSpecKey(resource, action)
	if key == "" {
		return ActionSpec{}, false
	}
	specs := protectedActionSpecIndex()
	spec, ok := specs[key]
	return spec, ok
}

func protectedActionSpecIndex() map[string]ActionSpec {
	protectedActionSpecsOnce.Do(func() {
		specs := make(map[string]ActionSpec)
		for _, spec := range ProtectedActionCatalog(nil) {
			key := protectedActionSpecKey(spec.Resource, spec.Action)
			if key == "" {
				continue
			}
			specs[key] = spec
		}
		protectedActionSpecs = specs
	})
	return protectedActionSpecs
}

func protectedActionSpecKey(resource, action string) string {
	resource = strings.ToLower(strings.TrimSpace(resource))
	action = strings.ToLower(strings.TrimSpace(action))
	if resource == "" || action == "" {
		return ""
	}
	return resource + "/" + action
}

func materializePublishedPath(pathTemplate string, params map[string]string) string {
	path := strings.TrimSpace(pathTemplate)
	if path == "" {
		return ""
	}
	for _, placeholder := range []struct {
		token string
		keys  []string
	}{
		{token: "{id}", keys: []string{"id", "client_id", "user_id", "tunnel_id", "host_id"}},
		{token: "{key}", keys: []string{"key", "ip"}},
	} {
		if !strings.Contains(path, placeholder.token) {
			continue
		}
		value := firstPublishedPathValue(params, placeholder.keys...)
		if value == "" {
			return ""
		}
		path = strings.ReplaceAll(path, placeholder.token, value)
	}
	if strings.Contains(path, "{") || strings.Contains(path, "}") {
		return ""
	}
	return path
}

func firstPublishedPathValue(params map[string]string, keys ...string) string {
	for _, key := range keys {
		if params == nil {
			break
		}
		if value := strings.TrimSpace(params[key]); value != "" {
			return value
		}
	}
	return ""
}

func actionSpecEnabled(cfg *servercfg.Snapshot, spec ActionSpec) bool {
	if cfg == nil {
		cfg = &servercfg.Snapshot{}
	}
	for _, feature := range spec.RequiredFeatures {
		if !requiredFeatureEnabled(cfg, feature) {
			return false
		}
	}
	return true
}

func requiredFeatureEnabled(cfg *servercfg.Snapshot, feature RequiredFeature) bool {
	switch feature {
	case RequiredFeatureAllowUserRegister:
		return cfg != nil && cfg.Feature.AllowUserRegister
	case RequiredFeatureDeviceEnrollment:
		return cfg != nil && cfg.Feature.AllowDeviceEnrollment
	default:
		return true
	}
}

type NodeRouteCatalog struct {
	APIBase             string
	Health              string
	Discovery           string
	Overview            string
	Dashboard           string
	Registration        string
	Operations          string
	Global              string
	BanList             string
	Users               string
	Clients             string
	ClientsConnections  string
	ClientsQR           string
	ClientsClear        string
	Tunnels             string
	Hosts               string
	HostCertSuggestion  string
	Config              string
	ConfigImport        string
	Status              string
	Changes             string
	CallbackQueue       string
	CallbackQueueReplay string
	CallbackQueueClear  string
	Webhooks            string
	RealtimeSubs        string
	UsageSnapshot       string
	Batch               string
	Traffic             string
	Kick                string
	Sync                string
	WebSocket           string
}

func NodeRoutePrefixes(baseURL string) []string {
	candidates := []string{NodeDirectRouteCatalog(baseURL).APIBase}
	prefixes := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, prefix := range candidates {
		prefix = strings.TrimRight(strings.TrimSpace(prefix), "/")
		if prefix == "" {
			continue
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func NodeDirectRouteCatalog(baseURL string) NodeRouteCatalog {
	return NodeRouteCatalogForPrefix(baseURL, "/api")
}

func NodeRouteCatalogForPrefix(baseURL, prefix string) NodeRouteCatalog {
	prefix = "/" + strings.Trim(strings.TrimSpace(prefix), "/")
	return NodeRouteCatalog{
		APIBase:             joinBase(baseURL, prefix),
		Health:              joinBase(baseURL, prefix+"/system/health"),
		Discovery:           joinBase(baseURL, prefix+"/system/discovery"),
		Overview:            joinBase(baseURL, prefix+"/system/overview"),
		Dashboard:           joinBase(baseURL, prefix+"/system/dashboard"),
		Registration:        joinBase(baseURL, prefix+"/system/registration"),
		Operations:          joinBase(baseURL, prefix+"/system/operations"),
		Global:              joinBase(baseURL, prefix+"/settings/global"),
		BanList:             joinBase(baseURL, prefix+"/security/bans"),
		Users:               joinBase(baseURL, prefix+"/users"),
		Clients:             joinBase(baseURL, prefix+"/clients"),
		ClientsConnections:  joinBase(baseURL, prefix+"/clients/:id/connections"),
		ClientsQR:           joinBase(baseURL, prefix+"/tools/qrcode"),
		ClientsClear:        joinBase(baseURL, prefix+"/clients/actions/clear"),
		Tunnels:             joinBase(baseURL, prefix+"/tunnels"),
		Hosts:               joinBase(baseURL, prefix+"/hosts"),
		HostCertSuggestion:  joinBase(baseURL, prefix+"/hosts/cert-suggestion"),
		Config:              joinBase(baseURL, prefix+"/system/export"),
		ConfigImport:        joinBase(baseURL, prefix+"/system/import"),
		Status:              joinBase(baseURL, prefix+"/system/status"),
		Changes:             joinBase(baseURL, prefix+"/system/changes"),
		CallbackQueue:       joinBase(baseURL, prefix+"/callbacks/queue"),
		CallbackQueueReplay: joinBase(baseURL, prefix+"/callbacks/queue/actions/replay"),
		CallbackQueueClear:  joinBase(baseURL, prefix+"/callbacks/queue/actions/clear"),
		Webhooks:            joinBase(baseURL, prefix+"/webhooks"),
		RealtimeSubs:        joinBase(baseURL, prefix+"/realtime/subscriptions"),
		UsageSnapshot:       joinBase(baseURL, prefix+"/system/usage-snapshot"),
		Batch:               joinBase(baseURL, prefix+"/batch"),
		Traffic:             joinBase(baseURL, prefix+"/traffic"),
		Kick:                joinBase(baseURL, prefix+"/clients/actions/kick"),
		Sync:                joinBase(baseURL, prefix+"/system/actions/sync"),
		WebSocket:           joinBase(baseURL, prefix+"/ws"),
	}
}

func (r NodeRouteCatalog) ApplyRuntimeConfig(dst map[string]interface{}) {
	if dst == nil {
		return
	}
	dst["api_base"] = r.APIBase
	dst["health"] = r.Health
	dst["discovery"] = r.Discovery
	dst["overview"] = r.Overview
	dst["dashboard"] = r.Dashboard
	dst["registration"] = r.Registration
	dst["operations"] = r.Operations
	dst["settings_global"] = r.Global
	dst["security_bans"] = r.BanList
	dst["users"] = r.Users
	dst["clients"] = r.Clients
	dst["clients_connections"] = r.ClientsConnections
	dst["clients_qrcode"] = r.ClientsQR
	dst["clients_clear"] = r.ClientsClear
	dst["tunnels"] = r.Tunnels
	dst["hosts"] = r.Hosts
	dst["host_cert_suggestion"] = r.HostCertSuggestion
	dst["system_export"] = r.Config
	dst["system_import"] = r.ConfigImport
	dst["status"] = r.Status
	dst["changes"] = r.Changes
	dst["callbacks_queue"] = r.CallbackQueue
	dst["callbacks_queue_replay"] = r.CallbackQueueReplay
	dst["callbacks_queue_clear"] = r.CallbackQueueClear
	dst["webhooks"] = r.Webhooks
	dst["realtime_subscriptions"] = r.RealtimeSubs
	dst["usage_snapshot"] = r.UsageSnapshot
	dst["batch"] = r.Batch
	dst["traffic"] = r.Traffic
	dst["clients_kick"] = r.Kick
	dst["system_sync"] = r.Sync
	dst["ws"] = r.WebSocket
}

func (r NodeRouteCatalog) ApplyDiscoveryRoutes(dst *ManagementRoutes) {
	if dst == nil {
		return
	}
	dst.Base = strings.TrimSuffix(strings.TrimSpace(r.APIBase), "/api")
	dst.APIBase = r.APIBase
	dst.Health = r.Health
	dst.Discovery = r.Discovery
	dst.Overview = r.Overview
	dst.Dashboard = r.Dashboard
	dst.Registration = r.Registration
	dst.Operations = r.Operations
	dst.SettingsGlobal = r.Global
	dst.SecurityBans = r.BanList
	dst.Users = r.Users
	dst.Clients = r.Clients
	dst.ClientsConnections = r.ClientsConnections
	dst.ClientsQRCode = r.ClientsQR
	dst.ClientsClear = r.ClientsClear
	dst.Tunnels = r.Tunnels
	dst.Hosts = r.Hosts
	dst.HostCertSuggestion = r.HostCertSuggestion
	dst.SystemExport = r.Config
	dst.SystemImport = r.ConfigImport
	dst.Status = r.Status
	dst.Changes = r.Changes
	dst.CallbacksQueue = r.CallbackQueue
	dst.CallbacksQueueReplay = r.CallbackQueueReplay
	dst.CallbacksQueueClear = r.CallbackQueueClear
	dst.Webhooks = r.Webhooks
	dst.RealtimeSubscriptions = r.RealtimeSubs
	dst.UsageSnapshot = r.UsageSnapshot
	dst.Batch = r.Batch
	dst.Traffic = r.Traffic
	dst.ClientsKick = r.Kick
	dst.SystemSync = r.Sync
	dst.WebSocket = r.WebSocket
}

func (r NodeRouteCatalog) OverviewURL(includeConfig bool) string {
	if !includeConfig {
		return r.Overview
	}
	if strings.Contains(r.Overview, "?") {
		return r.Overview + "&config=1"
	}
	return r.Overview + "?config=1"
}
