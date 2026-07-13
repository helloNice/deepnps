package api

import (
	"context"
	"reflect"
	"strings"
	"sync"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/servercfg"
	webservice "github.com/djylb/nps/web/service"
)

type RequestMetadata struct {
	NodeID    string `json:"node_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Source    string `json:"source,omitempty"`
}

type Event struct {
	Sequence  int64                  `json:"sequence,omitempty"`
	Timestamp int64                  `json:"timestamp,omitempty"`
	Name      string                 `json:"name"`
	Resource  string                 `json:"resource,omitempty"`
	Action    string                 `json:"action,omitempty"`
	Actor     *Actor                 `json:"actor,omitempty"`
	Metadata  RequestMetadata        `json:"metadata"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

type Hooks interface {
	OnManagementEvent(context.Context, Event) error
}

type NoopHooks struct{}

func (NoopHooks) OnManagementEvent(context.Context, Event) error {
	return nil
}

type App struct {
	NodeID         string
	Hooks          Hooks
	Services       webservice.Services
	ConfigProvider func() *servercfg.Snapshot
	servicesMu     sync.Mutex
}

type Options struct {
	NodeID            string
	Hooks             Hooks
	Services          *webservice.Services
	ConfigureServices func(*webservice.Services)
	ConfigProvider    func() *servercfg.Snapshot
}

func New(cfg *servercfg.Snapshot) *App {
	return NewWithOptions(cfg, Options{})
}

func NewWithOptions(cfg *servercfg.Snapshot, options Options) *App {
	var staticCfg *servercfg.Snapshot
	if cfg == nil {
		cfg = servercfg.ResolveProvider(options.ConfigProvider)
	} else {
		staticCfg = cfg
	}
	nodeID := strings.TrimSpace(options.NodeID)
	if nodeID == "" {
		nodeID = strings.TrimSpace(cfg.App.Name)
	}
	if nodeID == "" {
		nodeID = "nps"
	}
	var services webservice.Services
	if staticCfg != nil {
		services = webservice.Services{}
	} else {
		services = webservice.New()
	}
	if options.Services != nil {
		services = webservice.MergeServices(services, *options.Services)
	}
	hooks := options.Hooks
	if hooks == nil {
		hooks = NoopHooks{}
	}
	configProvider := options.ConfigProvider
	if configProvider == nil {
		if staticCfg != nil {
			configProvider = func() *servercfg.Snapshot {
				return staticCfg
			}
		} else {
			configProvider = servercfg.Current
		}
	}
	services = webservice.BindDefaultServices(services, configProvider)
	if options.ConfigureServices != nil {
		options.ConfigureServices(&services)
		services = webservice.BindDefaultServices(services, configProvider)
	}
	return &App{
		NodeID:         nodeID,
		Hooks:          hooks,
		Services:       services,
		ConfigProvider: configProvider,
	}
}

func (a *App) Emit(c Context, event Event) {
	if a == nil || a.Hooks == nil {
		return
	}
	baseCtx := context.Background()
	if c != nil {
		if event.Actor == nil {
			event.Actor = c.Actor()
		}
		if event.Metadata == (RequestMetadata{}) {
			event.Metadata = c.Metadata()
		}
		if ctx := c.BaseContext(); ctx != nil {
			baseCtx = ctx
		}
	}
	if event.Timestamp == 0 {
		event.Timestamp = common.TimeNow().Unix()
	}
	_ = a.Hooks.OnManagementEvent(baseCtx, event)
}

func (a *App) currentConfig() *servercfg.Snapshot {
	if a == nil {
		return servercfg.Current()
	}
	return servercfg.ResolveProvider(a.ConfigProvider)
}

func (a *App) CurrentConfig() *servercfg.Snapshot {
	return a.currentConfig()
}

func (a *App) permissionResolver() webservice.PermissionResolver {
	if a != nil && !isNilAppServiceValue(a.Services.Permissions) {
		return a.Services.Permissions
	}
	return webservice.DefaultPermissionResolver()
}

func (a *App) authorization() webservice.AuthorizationService {
	if a != nil && !isNilAppServiceValue(a.Services.Authz) {
		switch current := a.Services.Authz.(type) {
		case webservice.DefaultAuthorizationService:
			current.Resolver = a.permissionResolver()
			return current
		case *webservice.DefaultAuthorizationService:
			if current == nil {
				break
			}
			current.Resolver = a.permissionResolver()
			return current
		default:
			return a.Services.Authz
		}
	}
	return webservice.DefaultAuthorizationService{Resolver: a.permissionResolver()}
}

func (a *App) loginPolicy() webservice.LoginPolicyService {
	if a != nil && !isNilAppServiceValue(a.Services.LoginPolicy) {
		return a.Services.LoginPolicy
	}
	return webservice.SharedLoginPolicy()
}

func (a *App) backend() webservice.Backend {
	if a != nil {
		if !isNilAppServiceValue(a.Services.Backend.Repository) || !isNilAppServiceValue(a.Services.Backend.Runtime) {
			return a.Services.Backend
		}
	}
	return webservice.DefaultBackend()
}

func (a *App) nodeControl() webservice.NodeControlService {
	if a != nil && !isNilAppServiceValue(a.Services.NodeControl) {
		return a.Services.NodeControl
	}
	return webservice.DefaultNodeControlService{
		System:  a.system(),
		Authz:   a.authorization(),
		Backend: a.backend(),
	}
}

func (a *App) nodeStorage() webservice.NodeStorage {
	if a != nil && !isNilAppServiceValue(a.Services.NodeStorage) {
		return a.Services.NodeStorage
	}
	return webservice.DefaultNodeStorage{}
}

func (a *App) managementPlatforms() webservice.ManagementPlatformStore {
	if a != nil && !isNilAppServiceValue(a.Services.ManagementPlatforms) {
		return a.Services.ManagementPlatforms
	}
	return webservice.DefaultManagementPlatformStore{Backend: a.backend()}
}

func (a *App) managementPlatformRuntimeStatus() webservice.ManagementPlatformRuntimeStatusStore {
	if a == nil {
		return webservice.NewInMemoryManagementPlatformRuntimeStatusStore()
	}
	a.servicesMu.Lock()
	defer a.servicesMu.Unlock()
	if isNilAppServiceValue(a.Services.ManagementPlatformRuntimeStatus) {
		a.Services.ManagementPlatformRuntimeStatus = webservice.NewInMemoryManagementPlatformRuntimeStatusStore()
	}
	return a.Services.ManagementPlatformRuntimeStatus
}

func (a *App) runtimeStatus() webservice.NodeRuntimeStatusStore {
	if a == nil {
		return webservice.NewInMemoryNodeRuntimeStatusStore()
	}
	a.servicesMu.Lock()
	defer a.servicesMu.Unlock()
	if isNilAppServiceValue(a.Services.NodeRuntimeStatus) {
		a.Services.NodeRuntimeStatus = webservice.NewInMemoryNodeRuntimeStatusStore()
	}
	return a.Services.NodeRuntimeStatus
}

func (a *App) nodeOperations() webservice.NodeOperationStore {
	if a == nil {
		return webservice.NewInMemoryNodeOperationStore(webservice.NodeOperationDefaultHistoryLimit)
	}
	a.servicesMu.Lock()
	defer a.servicesMu.Unlock()
	if isNilAppServiceValue(a.Services.NodeOperations) {
		a.Services.NodeOperations = webservice.NewInMemoryNodeOperationStore(webservice.NodeOperationDefaultHistoryLimit)
	}
	return a.Services.NodeOperations
}

func (a *App) nodeTrafficReporter() webservice.NodeTrafficReporter {
	if a == nil {
		return &webservice.DefaultNodeTrafficReporter{ConfigProvider: servercfg.Current}
	}
	a.servicesMu.Lock()
	defer a.servicesMu.Unlock()
	if isNilAppServiceValue(a.Services.NodeTrafficReporter) {
		a.Services.NodeTrafficReporter = &webservice.DefaultNodeTrafficReporter{ConfigProvider: a.ConfigProvider}
	}
	return a.Services.NodeTrafficReporter
}

func (a *App) runtimeIdentity() webservice.NodeRuntimeIdentity {
	if a == nil {
		return webservice.NewNodeRuntimeIdentity()
	}
	a.servicesMu.Lock()
	defer a.servicesMu.Unlock()
	if isNilAppServiceValue(a.Services.NodeRuntimeIdentity) {
		a.Services.NodeRuntimeIdentity = webservice.NewNodeRuntimeIdentity()
	}
	return a.Services.NodeRuntimeIdentity
}

func (a *App) system() webservice.SystemService {
	if a != nil && !isNilAppServiceValue(a.Services.System) {
		return a.Services.System
	}
	return webservice.DefaultSystemService{}
}

func (a *App) deviceEnrollment() webservice.DeviceEnrollmentService {
	if a != nil && !isNilAppServiceValue(a.Services.DeviceEnrollment) {
		return a.Services.DeviceEnrollment
	}
	var configProvider func() *servercfg.Snapshot
	backend := webservice.DefaultBackend()
	if a != nil {
		configProvider = a.ConfigProvider
		backend = a.backend()
	}
	return webservice.NewDefaultDeviceEnrollmentService(configProvider, backend.Repository, backend)
}

func isNilAppServiceValue(value interface{}) bool {
	if value == nil {
		return true
	}
	current := reflect.ValueOf(value)
	switch current.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return current.IsNil()
	default:
		return false
	}
}
