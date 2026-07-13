package servercfg

import "sync/atomic"

type Snapshot struct {
	App      AppConfig
	Log      LogConfig
	Web      WebConfig
	Auth     AuthConfig
	Feature  FeatureConfig
	Security SecurityConfig
	Runtime  RuntimeConfig
	Network  NetworkConfig
	Bridge   BridgeConfig
	Proxy    ProxyConfig
	P2P      P2PConfig
}

type AppConfig struct {
	Name        string
	Timezone    string
	DNSServer   string
	GeoIPPath   string
	GeoSitePath string
	PprofIP     string
	PprofPort   string
	NTPServer   string
	NTPInterval int
}

type LogConfig struct {
	Type     string
	Level    string
	Path     string
	MaxFiles int
	MaxDays  int
	MaxSize  int
	Compress bool
	Color    bool
}

type WebConfig struct {
	BaseURL                    string
	HeadCustomCode             string
	Host                       string
	IP                         string
	Port                       int
	OpenSSL                    bool
	CloseOnNotFound            bool
	KeyFile                    string
	CertFile                   string
	Username                   string
	Password                   string
	TOTPSecret                 string
	StandaloneAllowedOrigins   string
	StandaloneAllowCredentials bool
	StandaloneTokenSecret      string
	StandaloneTokenTTLSeconds  int64
}

type AuthConfig struct {
	Key             string
	CryptKey        string
	HTTPOnlyPass    string
	AllowXRealIP    bool
	TrustedProxyIPs string
}

type FeatureConfig struct {
	AllowUserLogin          bool
	AllowUserRegister       bool
	AllowUserVkeyLogin      bool
	AllowUserChangeUsername bool
	OpenCaptcha             bool
	AllowFlowLimit          bool
	AllowRateLimit          bool
	AllowTimeLimit          bool
	AllowConnectionNumLimit bool
	AllowMultiIP            bool
	AllowTunnelNumLimit     bool
	AllowLocalProxy         bool
	AllowUserLocal          bool
	AllowSecretLocal        bool
	AllowDeviceEnrollment   bool
	SystemInfoDisplay       bool
	AllowPorts              string
}

type SecurityConfig struct {
	SecureMode        bool
	ForcePoW          bool
	PoWBits           int
	LoginBanTime      int64
	LoginIPBanTime    int64
	LoginUserBanTime  int64
	LoginMaxFailTimes int
	LoginMaxBody      int64
	LoginMaxSkew      int64
	LoginACLMode      int
	LoginACLRules     string
}

type RuntimeConfig struct {
	RunMode                   string
	MasterURL                 string
	NodeToken                 string
	ManagementPlatforms       []ManagementPlatformConfig
	PublicVKey                string
	VisitorVKey               string
	IPLimit                   string
	DisconnectTimeout         int
	FlowStoreInterval         int
	NodeEventLogSize          int
	NodeBatchMaxItems         int
	NodeIdempotencyTTL        int
	NodeTrafficReportInterval int
	NodeTrafficReportStep     int64
}

type ManagementPlatformConfig struct {
	PlatformID              string
	Token                   string
	ControlScope            string
	Enabled                 bool
	ServiceUsername         string
	MasterURL               string
	ConnectMode             string
	ReverseWSURL            string
	ReverseEnabled          bool
	ReverseHeartbeatSeconds int
	CallbackURL             string
	CallbackEnabled         bool
	CallbackTimeoutSeconds  int
	CallbackRetryMax        int
	CallbackRetryBackoffSec int
	CallbackQueueMax        int
	CallbackSigningKey      string
}

type NetworkConfig struct {
	BridgeIP               string
	BridgeHost             string
	BridgeTCPIP            string
	BridgeKCPIP            string
	BridgeQUICIP           string
	BridgeTLSIP            string
	BridgeWSIP             string
	BridgeWSSIP            string
	BridgePort             int
	BridgeTCPPort          int
	BridgeKCPPort          int
	BridgeQUICPort         int
	BridgeTLSPort          int
	BridgeWSPort           int
	BridgeWSSPort          int
	BridgePath             string
	BridgeTrustedIPs       string
	BridgeRealIPHeader     string
	HTTPProxyIP            string
	HTTPProxyPort          int
	HTTPSProxyPort         int
	HTTP3ProxyPort         int
	WebIP                  string
	WebPort                int
	P2PIP                  string
	P2PPort                int
	QUICALPN               string
	QUICALPNList           []string
	QUICKeepAlivePeriod    int
	QUICMaxIdleTimeout     int
	QUICMaxIncomingStreams int64
	MuxPingInterval        int
}

type BridgeConfig struct {
	Addr              string
	Type              string
	PrimaryType       string
	SelectMode        string
	CertFile          string
	KeyFile           string
	TCPEnable         bool
	KCPEnable         bool
	QUICEnable        bool
	TLSEnable         bool
	WSEnable          bool
	WSSEnable         bool
	ServerTCPEnabled  bool
	ServerKCPEnabled  bool
	ServerQUICEnabled bool
	ServerTLSEnabled  bool
	ServerWSEnabled   bool
	ServerWSSEnabled  bool
	Display           BridgeDisplayConfig
}

type BridgeDisplayConfig struct {
	Path string
	TCP  BridgeDisplayEndpoint
	KCP  BridgeDisplayEndpoint
	QUIC BridgeDisplayEndpoint
	TLS  BridgeDisplayEndpoint
	WS   BridgeDisplayEndpoint
	WSS  BridgeDisplayEndpoint
}

type BridgeDisplayEndpoint struct {
	Show bool
	IP   string
	Port string
	ALPN string
}

type ProxyConfig struct {
	AddOriginHeader    bool
	ResponseTimeout    int
	ErrorPage          string
	ErrorPageTimeLimit string
	ErrorPageFlowLimit string
	ErrorAlways        bool
	BridgeHTTP3        bool
	ForceAutoSSL       bool
	SSL                SSLConfig
}

type SSLConfig struct {
	Email           string
	CA              string
	Path            string
	ZeroSSLAPI      string
	DefaultCertFile string
	DefaultKeyFile  string
	CacheMax        int
	CacheReload     int
	CacheIdle       int
}

type P2PConfig struct {
	ProbeExtraReply           bool
	ForcePredictOnRestricted  bool
	EnableTargetSpray         bool
	EnableBirthdayAttack      bool
	EnableUPNPPortmap         bool
	EnablePCPPortmap          bool
	EnableNATPMPPortmap       bool
	PortmapLeaseSeconds       int
	DefaultPredictionInterval int
	TargetSpraySpan           int
	TargetSprayRounds         int
	TargetSprayBurst          int
	TargetSprayPacketSleepMs  int
	TargetSprayBurstGapMs     int
	TargetSprayPhaseGapMs     int
	BirthdayListenPorts       int
	BirthdayTargetsPerPort    int
	ProbeTimeoutMs            int
	HandshakeTimeoutMs        int
	TransportTimeoutMs        int
}

type valueReader struct {
	values map[string]any
}

var (
	currentSnapshot atomic.Pointer[Snapshot]
	defaultSnapshot = buildSnapshot(nil)
)

func init() {
	currentSnapshot.Store(defaultSnapshot)
}

func Current() *Snapshot {
	if snapshot := currentSnapshot.Load(); snapshot != nil {
		return snapshot
	}
	return defaultSnapshot
}

func buildSnapshot(values map[string]any) *Snapshot {
	r := valueReader{values: values}
	cfg := &Snapshot{}

	cfg.App = buildAppConfig(r)
	cfg.Log = buildLogConfig(r)
	cfg.Web = buildWebConfig(r)
	cfg.Auth = buildAuthConfig(r)
	cfg.Feature = buildFeatureConfig(r)
	cfg.Security = buildSecurityConfig(r)
	cfg.Runtime = buildRuntimeConfig(r)
	cfg.Network = buildNetworkConfig(r, cfg.Web)
	cfg.Bridge = buildBridgeConfig(r, cfg.Network)
	cfg.Proxy = buildProxyConfig(r)

	cfg.P2P = buildP2PConfig(r)

	return cfg
}

func (r valueReader) stringValue(keys ...string) string {
	return r.stringDefault("", keys...)
}

func (r valueReader) rawValue(keys ...string) (any, bool) {
	for _, key := range keys {
		value, err := lookupValue(r.values, key)
		if err == nil {
			return value, true
		}
	}
	return nil, false
}

func (r valueReader) stringDefault(defaultValue string, keys ...string) string {
	for _, key := range keys {
		value, err := lookupValue(r.values, key)
		if err != nil {
			continue
		}
		if text := stringifyValue(value); text != "" {
			return text
		}
	}
	return defaultValue
}

func (r valueReader) boolDefault(defaultValue bool, keys ...string) bool {
	for _, key := range keys {
		value, err := lookupValue(r.values, key)
		if err != nil {
			continue
		}
		if parsed, err := toBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func (r valueReader) intDefault(defaultValue int, keys ...string) int {
	for _, key := range keys {
		value, err := lookupValue(r.values, key)
		if err != nil {
			continue
		}
		if parsed, err := toInt(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func (r valueReader) intValue(keys ...string) (int, bool) {
	for _, key := range keys {
		value, err := lookupValue(r.values, key)
		if err != nil {
			continue
		}
		if parsed, err := toInt(value); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func (r valueReader) int64Default(defaultValue int64, keys ...string) int64 {
	for _, key := range keys {
		value, err := lookupValue(r.values, key)
		if err != nil {
			continue
		}
		if parsed, err := toInt64(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func (r valueReader) int64Value(keys ...string) (int64, bool) {
	for _, key := range keys {
		value, err := lookupValue(r.values, key)
		if err != nil {
			continue
		}
		if parsed, err := toInt64(value); err == nil {
			return parsed, true
		}
	}
	return 0, false
}
