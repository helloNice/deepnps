package service

import (
	"reflect"

	"github.com/djylb/nps/lib/servercfg"
)

// Services groups the default application services behind replaceable interfaces.
// Swapping framework or storage backends should not require transport-layer rewrites.
type Services struct {
	Backend                         Backend
	System                          SystemService
	Permissions                     PermissionResolver
	Auth                            AuthService
	Authz                           AuthorizationService
	LoginPolicy                     LoginPolicyService
	NodeControl                     NodeControlService
	NodeStorage                     NodeStorage
	NodeRuntimeIdentity             NodeRuntimeIdentity
	NodeRuntimeStatus               NodeRuntimeStatusStore
	NodeOperations                  NodeOperationStore
	NodeTrafficReporter             NodeTrafficReporter
	ManagementPlatforms             ManagementPlatformStore
	ManagementPlatformRuntimeStatus ManagementPlatformRuntimeStatusStore
	Clients                         ClientService
	Users                           UserService
	Globals                         GlobalService
	Index                           IndexService
	DeviceEnrollment                DeviceEnrollmentService
}

func BindDefaultServices(services Services, configProvider func() *servercfg.Snapshot) Services {
	backend := normalizeServicesBackend(services.Backend)
	services.Backend = backend
	repo := backend.repo()
	runtime := backend.runtime()
	if configProvider == nil {
		configProvider = servercfg.Current
	}

	services.System = bindSystemService(services.System)
	services.Permissions = bindPermissionResolver(services.Permissions)
	services.LoginPolicy = bindLoginPolicyService(services.LoginPolicy, configProvider)
	services.NodeStorage = bindNodeStorage(services.NodeStorage)
	services.NodeRuntimeIdentity = bindNodeRuntimeIdentity(services.NodeRuntimeIdentity)
	services.NodeRuntimeStatus = bindNodeRuntimeStatusStore(services.NodeRuntimeStatus)
	services.NodeOperations = bindNodeOperationStore(services.NodeOperations)
	services.NodeTrafficReporter = bindNodeTrafficReporter(services.NodeTrafficReporter, configProvider)
	services.ManagementPlatformRuntimeStatus = bindManagementPlatformRuntimeStatusStore(services.ManagementPlatformRuntimeStatus)

	services.Authz = bindAuthorizationService(services.Authz, services.Permissions, repo, backend)
	services.Auth = bindAuthService(services.Auth, services.Permissions, configProvider, repo, backend)
	services.Clients = bindClientService(services.Clients, configProvider, repo, runtime, backend)
	services.Users = bindUserService(services.Users, configProvider, repo, runtime, backend)
	services.Globals = bindGlobalService(services.Globals, services.LoginPolicy, repo, backend)
	services.Index = bindIndexService(services.Index, repo, runtime, backend)
	services.DeviceEnrollment = bindDeviceEnrollmentService(services.DeviceEnrollment, configProvider, repo, backend)
	services.ManagementPlatforms = bindManagementPlatformStore(services.ManagementPlatforms, repo, backend)
	services.NodeControl = bindNodeControlService(services.NodeControl, services.System, services.Authz, repo, runtime, backend)
	return services
}

func MergeServices(base, overrides Services) Services {
	merged := base
	if !isNilServiceValue(overrides.Backend.Repository) {
		merged.Backend.Repository = overrides.Backend.Repository
	}
	if !isNilServiceValue(overrides.Backend.Runtime) {
		merged.Backend.Runtime = overrides.Backend.Runtime
	}
	mergeOptionalService(&merged.System, overrides.System)
	mergeOptionalService(&merged.Permissions, overrides.Permissions)
	mergeOptionalService(&merged.Auth, overrides.Auth)
	mergeOptionalService(&merged.Authz, overrides.Authz)
	mergeOptionalService(&merged.LoginPolicy, overrides.LoginPolicy)
	mergeOptionalService(&merged.NodeControl, overrides.NodeControl)
	mergeOptionalService(&merged.NodeStorage, overrides.NodeStorage)
	mergeOptionalService(&merged.NodeRuntimeIdentity, overrides.NodeRuntimeIdentity)
	mergeOptionalService(&merged.NodeRuntimeStatus, overrides.NodeRuntimeStatus)
	mergeOptionalService(&merged.NodeOperations, overrides.NodeOperations)
	mergeOptionalService(&merged.NodeTrafficReporter, overrides.NodeTrafficReporter)
	mergeOptionalService(&merged.ManagementPlatforms, overrides.ManagementPlatforms)
	mergeOptionalService(&merged.ManagementPlatformRuntimeStatus, overrides.ManagementPlatformRuntimeStatus)
	mergeOptionalService(&merged.Clients, overrides.Clients)
	mergeOptionalService(&merged.Users, overrides.Users)
	mergeOptionalService(&merged.Globals, overrides.Globals)
	mergeOptionalService(&merged.Index, overrides.Index)
	mergeOptionalService(&merged.DeviceEnrollment, overrides.DeviceEnrollment)
	return merged
}

func New() Services {
	return BindDefaultServices(Services{
		Backend:     DefaultBackend(),
		System:      DefaultSystemService{},
		Permissions: DefaultPermissionResolver(),
		LoginPolicy: SharedLoginPolicy(),
	}, servercfg.Current)
}

func normalizeServicesBackend(backend Backend) Backend {
	defaultBackend := DefaultBackend()
	if isNilServiceValue(backend.Repository) {
		backend.Repository = defaultBackend.Repository
	}
	if isNilServiceValue(backend.Runtime) {
		backend.Runtime = defaultBackend.Runtime
	}
	return backend
}

func bindSystemService(service SystemService) SystemService {
	if isNilServiceValue(service) {
		return DefaultSystemService{}
	}
	switch current := service.(type) {
	case DefaultSystemService:
		return current
	case *DefaultSystemService:
		if current == nil {
			return DefaultSystemService{}
		}
		return current
	default:
		return service
	}
}

func bindPermissionResolver(resolver PermissionResolver) PermissionResolver {
	if isNilServiceValue(resolver) {
		return DefaultPermissionResolver()
	}
	return resolver
}

func bindLoginPolicyService(service LoginPolicyService, configProvider func() *servercfg.Snapshot) LoginPolicyService {
	if isNilServiceValue(service) {
		current := NewDefaultLoginPolicy(configProvider)
		current.ConfigProvider = configProvider
		return current
	}
	if current, ok := service.(*DefaultLoginPolicy); ok {
		if current == nil {
			current = NewDefaultLoginPolicy(configProvider)
		}
		current.ConfigProvider = configProvider
		return current
	}
	return service
}

func bindNodeStorage(storage NodeStorage) NodeStorage {
	if isNilServiceValue(storage) {
		return DefaultNodeStorage{}
	}
	switch current := storage.(type) {
	case DefaultNodeStorage:
		return current
	case *DefaultNodeStorage:
		if current == nil {
			return DefaultNodeStorage{}
		}
		return current
	default:
		return storage
	}
}

func bindNodeRuntimeIdentity(identity NodeRuntimeIdentity) NodeRuntimeIdentity {
	if isNilServiceValue(identity) {
		return NewNodeRuntimeIdentity()
	}
	if current, ok := identity.(*StaticNodeRuntimeIdentity); ok {
		if current == nil {
			return NewNodeRuntimeIdentity()
		}
		return current
	}
	return identity
}

func bindNodeRuntimeStatusStore(store NodeRuntimeStatusStore) NodeRuntimeStatusStore {
	if isNilServiceValue(store) {
		return NewInMemoryNodeRuntimeStatusStore()
	}
	if current, ok := store.(*InMemoryNodeRuntimeStatusStore); ok {
		if current == nil {
			return NewInMemoryNodeRuntimeStatusStore()
		}
		return current
	}
	return store
}

func bindNodeOperationStore(store NodeOperationStore) NodeOperationStore {
	if isNilServiceValue(store) {
		return NewInMemoryNodeOperationStore(NodeOperationDefaultHistoryLimit)
	}
	if current, ok := store.(*InMemoryNodeOperationStore); ok {
		if current == nil {
			return NewInMemoryNodeOperationStore(NodeOperationDefaultHistoryLimit)
		}
		return current
	}
	return store
}

func bindNodeTrafficReporter(reporter NodeTrafficReporter, configProvider func() *servercfg.Snapshot) NodeTrafficReporter {
	if isNilServiceValue(reporter) {
		return &DefaultNodeTrafficReporter{ConfigProvider: configProvider}
	}
	if current, ok := reporter.(*DefaultNodeTrafficReporter); ok {
		if current == nil {
			current = &DefaultNodeTrafficReporter{}
		}
		current.ConfigProvider = configProvider
		return current
	}
	return reporter
}

func bindManagementPlatformRuntimeStatusStore(store ManagementPlatformRuntimeStatusStore) ManagementPlatformRuntimeStatusStore {
	if isNilServiceValue(store) {
		return NewInMemoryManagementPlatformRuntimeStatusStore()
	}
	if current, ok := store.(*InMemoryManagementPlatformRuntimeStatusStore); ok {
		if current == nil {
			return NewInMemoryManagementPlatformRuntimeStatusStore()
		}
		return current
	}
	return store
}

func bindAuthorizationService(service AuthorizationService, resolver PermissionResolver, repo Repository, backend Backend) AuthorizationService {
	if isNilServiceValue(service) {
		current := DefaultAuthorizationService{}
		current.Resolver = resolver
		if current.Repo == nil {
			current.Repo = repo
		}
		current.Backend = backend
		return current
	}
	switch current := service.(type) {
	case DefaultAuthorizationService:
		current.Resolver = resolver
		if current.Repo == nil {
			current.Repo = repo
		}
		current.Backend = backend
		return current
	case *DefaultAuthorizationService:
		if current == nil {
			current = &DefaultAuthorizationService{}
		}
		current.Resolver = resolver
		if current.Repo == nil {
			current.Repo = repo
		}
		current.Backend = backend
		return current
	default:
		return service
	}
}

func bindAuthService(service AuthService, resolver PermissionResolver, configProvider func() *servercfg.Snapshot, repo Repository, backend Backend) AuthService {
	if isNilServiceValue(service) {
		current := DefaultAuthService{}
		current.Resolver = resolver
		current.ConfigProvider = configProvider
		if current.Repo == nil {
			current.Repo = repo
		}
		current.Backend = backend
		return current
	}
	switch current := service.(type) {
	case DefaultAuthService:
		current.Resolver = resolver
		current.ConfigProvider = configProvider
		if current.Repo == nil {
			current.Repo = repo
		}
		current.Backend = backend
		return current
	case *DefaultAuthService:
		if current == nil {
			current = &DefaultAuthService{}
		}
		current.Resolver = resolver
		current.ConfigProvider = configProvider
		if current.Repo == nil {
			current.Repo = repo
		}
		current.Backend = backend
		return current
	default:
		return service
	}
}

func bindClientService(service ClientService, configProvider func() *servercfg.Snapshot, repo Repository, runtime Runtime, backend Backend) ClientService {
	if isNilServiceValue(service) {
		current := DefaultClientService{}
		current.ConfigProvider = configProvider
		if current.Repo == nil {
			current.Repo = repo
		}
		if current.Runtime == nil {
			current.Runtime = runtime
		}
		current.Backend = backend
		return current
	}
	switch current := service.(type) {
	case DefaultClientService:
		current.ConfigProvider = configProvider
		if current.Repo == nil {
			current.Repo = repo
		}
		if current.Runtime == nil {
			current.Runtime = runtime
		}
		current.Backend = backend
		return current
	case *DefaultClientService:
		if current == nil {
			current = &DefaultClientService{}
		}
		current.ConfigProvider = configProvider
		if current.Repo == nil {
			current.Repo = repo
		}
		if current.Runtime == nil {
			current.Runtime = runtime
		}
		current.Backend = backend
		return current
	default:
		return service
	}
}

func bindUserService(service UserService, configProvider func() *servercfg.Snapshot, repo Repository, runtime Runtime, backend Backend) UserService {
	if isNilServiceValue(service) {
		current := DefaultUserService{}
		current.ConfigProvider = configProvider
		if current.Repo == nil {
			current.Repo = repo
		}
		if current.Runtime == nil {
			current.Runtime = runtime
		}
		current.Backend = backend
		return current
	}
	switch current := service.(type) {
	case DefaultUserService:
		current.ConfigProvider = configProvider
		if current.Repo == nil {
			current.Repo = repo
		}
		if current.Runtime == nil {
			current.Runtime = runtime
		}
		current.Backend = backend
		return current
	case *DefaultUserService:
		if current == nil {
			current = &DefaultUserService{}
		}
		current.ConfigProvider = configProvider
		if current.Repo == nil {
			current.Repo = repo
		}
		if current.Runtime == nil {
			current.Runtime = runtime
		}
		current.Backend = backend
		return current
	default:
		return service
	}
}

func bindGlobalService(service GlobalService, loginPolicy LoginPolicyService, repo Repository, backend Backend) GlobalService {
	if isNilServiceValue(service) {
		current := DefaultGlobalService{}
		current.LoginPolicy = loginPolicy
		if current.Repo == nil {
			current.Repo = repo
		}
		current.Backend = backend
		return current
	}
	switch current := service.(type) {
	case DefaultGlobalService:
		current.LoginPolicy = loginPolicy
		if current.Repo == nil {
			current.Repo = repo
		}
		current.Backend = backend
		return current
	case *DefaultGlobalService:
		if current == nil {
			current = &DefaultGlobalService{}
		}
		current.LoginPolicy = loginPolicy
		if current.Repo == nil {
			current.Repo = repo
		}
		current.Backend = backend
		return current
	default:
		return service
	}
}

func bindIndexService(service IndexService, repo Repository, runtime Runtime, backend Backend) IndexService {
	if isNilServiceValue(service) {
		current := DefaultIndexService{}
		if current.Repo == nil {
			current.Repo = repo
		}
		if current.Runtime == nil {
			current.Runtime = runtime
		}
		if current.QuotaStore == nil {
			current.QuotaStore = DefaultQuotaStore{}
		}
		current.Backend = backend
		return current
	}
	switch current := service.(type) {
	case DefaultIndexService:
		if current.Repo == nil {
			current.Repo = repo
		}
		if current.Runtime == nil {
			current.Runtime = runtime
		}
		if current.QuotaStore == nil {
			current.QuotaStore = DefaultQuotaStore{}
		}
		current.Backend = backend
		return current
	case *DefaultIndexService:
		if current == nil {
			current = &DefaultIndexService{}
		}
		if current.Repo == nil {
			current.Repo = repo
		}
		if current.Runtime == nil {
			current.Runtime = runtime
		}
		if current.QuotaStore == nil {
			current.QuotaStore = DefaultQuotaStore{}
		}
		current.Backend = backend
		return current
	default:
		return service
	}
}

func bindDeviceEnrollmentService(service DeviceEnrollmentService, configProvider func() *servercfg.Snapshot, repo Repository, backend Backend) DeviceEnrollmentService {
	if isNilServiceValue(service) {
		return NewDefaultDeviceEnrollmentService(configProvider, repo, backend)
	}
	switch current := service.(type) {
	case *DefaultDeviceEnrollmentService:
		if current == nil {
			return NewDefaultDeviceEnrollmentService(configProvider, repo, backend)
		}
		if current.ConfigProvider == nil {
			current.ConfigProvider = configProvider
		}
		if current.Repo == nil {
			current.Repo = repo
		}
		current.Backend = backend
		return current
	default:
		return service
	}
}

func bindManagementPlatformStore(service ManagementPlatformStore, repo Repository, backend Backend) ManagementPlatformStore {
	if isNilServiceValue(service) {
		current := DefaultManagementPlatformStore{}
		if current.Repo == nil {
			current.Repo = repo
		}
		current.Backend = backend
		return current
	}
	switch current := service.(type) {
	case DefaultManagementPlatformStore:
		if current.Repo == nil {
			current.Repo = repo
		}
		current.Backend = backend
		return current
	case *DefaultManagementPlatformStore:
		if current == nil {
			current = &DefaultManagementPlatformStore{}
		}
		if current.Repo == nil {
			current.Repo = repo
		}
		current.Backend = backend
		return current
	default:
		return service
	}
}

func bindNodeControlService(service NodeControlService, system SystemService, authz AuthorizationService, repo Repository, runtime Runtime, backend Backend) NodeControlService {
	if isNilServiceValue(service) {
		current := DefaultNodeControlService{}
		current.System = system
		current.Authz = authz
		if current.Repo == nil {
			current.Repo = repo
		}
		if current.Runtime == nil {
			current.Runtime = runtime
		}
		current.Backend = backend
		return current
	}
	switch current := service.(type) {
	case DefaultNodeControlService:
		current.System = system
		current.Authz = authz
		if current.Repo == nil {
			current.Repo = repo
		}
		if current.Runtime == nil {
			current.Runtime = runtime
		}
		current.Backend = backend
		return current
	case *DefaultNodeControlService:
		if current == nil {
			current = &DefaultNodeControlService{}
		}
		current.System = system
		current.Authz = authz
		if current.Repo == nil {
			current.Repo = repo
		}
		if current.Runtime == nil {
			current.Runtime = runtime
		}
		current.Backend = backend
		return current
	default:
		return service
	}
}

func isNilServiceValue(value interface{}) bool {
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

func mergeOptionalService[T any](dst *T, override T) {
	if dst == nil || isNilServiceValue(override) {
		return
	}
	*dst = override
}
