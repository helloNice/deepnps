package file

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/nps/lib/policy"
	"github.com/djylb/nps/lib/rate"
)

var (
	clientSetupHookMu sync.RWMutex
	clientSetupHook   func(*Client)
)

const (
	AclOff       = 0
	AclWhitelist = 1
	AclBlacklist = 2
)

type Flow struct {
	ExportFlow int64
	InletFlow  int64
	FlowLimit  int64
	TimeLimit  time.Time
	onDelta    func(in, out int64)
	sync.RWMutex
}

type TrafficStats struct {
	ExportBytes int64 `json:"export_bytes"`
	InletBytes  int64 `json:"inlet_bytes"`
}

type User struct {
	Id                 int
	Username           string
	Password           string
	TOTPSecret         string
	Kind               string
	ExternalPlatformID string
	Hidden             bool
	Status             int
	ExpireAt           int64
	FlowLimit          int64
	TotalFlow          *Flow
	MaxClients         int
	MaxTunnels         int
	MaxHosts           int
	MaxConnections     int
	RateLimit          int
	EntryAclMode       int
	EntryAclRules      string
	DestAclMode        int
	DestAclRules       string
	Revision           int64
	UpdatedAt          int64
	ExpectedRevision   int64      `json:"-"`
	NowConn            int32      `json:"-"`
	Rate               *rate.Rate `json:"-"`
	TotalTraffic       *TrafficStats
	TotalMeter         *rate.Meter `json:"-"`
	sourcePolicy       *policy.SourceIPPolicy
	destIPPolicy       *policy.SourceIPPolicy
	destPolicy         *policy.DestinationPolicy
	sync.RWMutex
}

type Config struct {
	U        string
	P        string
	Compress bool
	Crypt    bool
}

type Client struct {
	Cnf               *Config
	Id                int
	UserId            int
	OwnerUserID       int
	ManagerUserIDs    []int
	SourceType        string
	SourcePlatformID  string
	SourceActorID     string
	DevicePublicKey   string
	DeviceKeyID       string
	DeviceEnrolledAt  int64
	Revision          int64
	UpdatedAt         int64
	ExpectedRevision  int64 `json:"-"`
	VerifyKey         string
	Mode              string
	Addr              string
	LocalAddr         string
	Remark            string
	Status            bool
	IsConnect         bool
	ExpireAt          int64
	FlowLimit         int64
	RateLimit         int
	Flow              *Flow
	ExportFlow        int64
	InletFlow         int64
	Rate              *rate.Rate `json:"-"`
	BridgeTraffic     *TrafficStats
	ServiceTraffic    *TrafficStats
	BridgeMeter       *rate.Meter `json:"-"`
	ServiceMeter      *rate.Meter `json:"-"`
	TotalMeter        *rate.Meter `json:"-"`
	NoStore           bool
	NoDisplay         bool
	MaxConn           int
	NowConn           int32
	ConfigConnAllow   bool
	MaxTunnelNum      int
	Version           string
	EntryAclMode      int
	EntryAclRules     string
	CreateTime        string
	LastOnlineTime    string
	legacyBlackIPList []string
	legacyWebLogin    *legacyClientWebLoginImport
	sourcePolicy      *policy.SourceIPPolicy
	ownerUser         *User
	sync.RWMutex
}

type Tunnel struct {
	Id               int
	Revision         int64
	UpdatedAt        int64
	ExpectedRevision int64 `json:"-"`
	Port             int
	ServerIp         string
	Mode             string
	Status           bool
	RunStatus        bool
	Client           *Client
	Ports            string
	ExpireAt         int64
	FlowLimit        int64
	RateLimit        int
	Flow             *Flow
	Rate             *rate.Rate `json:"-"`
	ServiceTraffic   *TrafficStats
	ServiceMeter     *rate.Meter `json:"-"`
	MaxConn          int
	NowConn          int32
	Password         string
	Remark           string
	TargetAddr       string
	TargetType       string
	EntryAclMode     int
	EntryAclRules    string
	entryPolicy      *policy.SourceIPPolicy
	DestAclMode      int
	DestAclRules     string
	DestAclSet       *policy.DestinationPolicy `json:"-"`
	destIPPolicy     *policy.SourceIPPolicy
	destPolicy       *policy.DestinationPolicy
	NoStore          bool
	IsHttp           bool
	HttpProxy        bool
	Socks5Proxy      bool
	LocalPath        string
	StripPre         string
	ReadOnly         bool
	Target           *Target
	UserAuth         *MultiAccount
	MultiAccount     *MultiAccount
	Health
	runtimeRouteUUID   string
	runtimeOwners      *runtimeOwnerPool[*Tunnel]
	runtimeConnCounter *int32
	sync.RWMutex
}

type Health struct {
	HealthCheckTimeout  int
	HealthMaxFail       int
	HealthCheckInterval int
	HealthNextTime      time.Time
	HealthMap           map[string]int
	HttpHealthUrl       string
	HealthRemoveArr     []string
	HealthCheckType     string
	HealthCheckTarget   string
	sync.RWMutex
}

type Host struct {
	Id                 int
	Revision           int64
	UpdatedAt          int64
	ExpectedRevision   int64 `json:"-"`
	Host               string
	HeaderChange       string
	RespHeaderChange   string
	HostChange         string
	Location           string
	PathRewrite        string
	Remark             string
	Scheme             string
	RedirectURL        string
	HttpsJustProxy     bool
	TlsOffload         bool
	AutoSSL            bool
	CertType           string
	CertHash           string
	CertFile           string
	KeyFile            string
	NoStore            bool
	IsClose            bool
	AutoHttps          bool
	AutoCORS           bool
	CompatMode         bool
	ExpireAt           int64
	FlowLimit          int64
	RateLimit          int
	Flow               *Flow
	Rate               *rate.Rate `json:"-"`
	ServiceTraffic     *TrafficStats
	ServiceMeter       *rate.Meter `json:"-"`
	MaxConn            int
	NowConn            int32
	Client             *Client
	EntryAclMode       int
	EntryAclRules      string
	entryPolicy        *policy.SourceIPPolicy
	TargetIsHttps      bool
	Target             *Target
	UserAuth           *MultiAccount
	MultiAccount       *MultiAccount
	Health             `json:"-"`
	runtimeRouteUUID   string
	runtimeOwners      *runtimeOwnerPool[*Host]
	runtimeConnCounter *int32
	sync.RWMutex
}

type Target struct {
	nowIndex        int
	TargetStr       string
	TargetArr       []string
	LocalProxy      bool
	ProxyProtocol   int
	targetArrSource string
	sync.RWMutex
}

type MultiAccount struct {
	Content          string
	AccountMap       map[string]string
	accountMapSource string
}

type Glob struct {
	EntryAclMode      int
	EntryAclRules     string
	legacyBlackIPList []string
	sourcePolicy      *policy.SourceIPPolicy
	sync.RWMutex
}

func (s *Flow) Add(in, out int64) {
	if s == nil {
		return
	}
	s.Lock()
	s.InletFlow += in
	s.ExportFlow += out
	onDelta := s.onDelta
	s.Unlock()
	if onDelta != nil && (in != 0 || out != 0) {
		onDelta(in, out)
	}
}

func (s *Flow) Sub(in, out int64) {
	if s == nil {
		return
	}
	s.Lock()
	s.InletFlow -= in
	s.ExportFlow -= out
	if s.InletFlow < 0 {
		s.InletFlow = 0
	}
	if s.ExportFlow < 0 {
		s.ExportFlow = 0
	}
	s.Unlock()
}

func (s *Flow) SetOnDelta(fn func(in, out int64)) {
	if s == nil {
		return
	}
	s.Lock()
	s.onDelta = fn
	s.Unlock()
}

func flowSnapshot(s *Flow) (int64, int64) {
	if s == nil {
		return 0, 0
	}
	s.RLock()
	defer s.RUnlock()
	return s.InletFlow, s.ExportFlow
}

func (s *TrafficStats) Add(in, out int64) (int64, int64, int64) {
	if s == nil {
		return 0, 0, 0
	}
	currentIn := atomic.LoadInt64(&s.InletBytes)
	currentOut := atomic.LoadInt64(&s.ExportBytes)
	if in != 0 {
		currentIn = atomic.AddInt64(&s.InletBytes, in)
	}
	if out != 0 {
		currentOut = atomic.AddInt64(&s.ExportBytes, out)
	}
	return currentIn, currentOut, currentIn + currentOut
}

func (s *TrafficStats) Snapshot() (int64, int64, int64) {
	if s == nil {
		return 0, 0, 0
	}
	in := atomic.LoadInt64(&s.InletBytes)
	out := atomic.LoadInt64(&s.ExportBytes)
	return in, out, in + out
}

func (s *TrafficStats) Reset() {
	if s == nil {
		return
	}
	atomic.StoreInt64(&s.InletBytes, 0)
	atomic.StoreInt64(&s.ExportBytes, 0)
}

func rateSnapshot(m *rate.Meter) (int64, int64, int64) {
	if m == nil {
		return 0, 0, 0
	}
	return m.Snapshot()
}

func normalizeNonNegativeConnectionLimit(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func NewMultiAccount(content string) *MultiAccount {
	account := &MultiAccount{Content: normalizeMultiAccountContent(content)}
	account.AccountMap = parseMultiAccountContent(account.Content)
	account.accountMapSource = account.Content
	return account
}

func normalizeMultiAccount(account *MultiAccount) *MultiAccount {
	if account == nil {
		return nil
	}
	account.Content = normalizeMultiAccountContent(account.Content)
	if account.Content != "" {
		account.AccountMap = parseMultiAccountContent(account.Content)
		account.accountMapSource = account.Content
		if len(account.AccountMap) == 0 {
			account.AccountMap = nil
		}
		return account
	}
	if len(account.AccountMap) == 0 {
		account.AccountMap = nil
		account.accountMapSource = ""
		return account
	}
	account.accountMapSource = ""
	return account
}

func normalizeMultiAccountContent(content string) string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	return strings.TrimSpace(content)
}

func parseMultiAccountContent(content string) map[string]string {
	content = normalizeMultiAccountContent(content)
	if content == "" {
		return nil
	}
	lines := strings.Split(content, "\n")
	accountMap := make(map[string]string, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		index := strings.Index(line, "=")
		if index < 0 {
			accountMap[line] = ""
			continue
		}
		key := strings.TrimSpace(line[:index])
		if key == "" {
			continue
		}
		accountMap[key] = strings.TrimSpace(line[index+1:])
	}
	if len(accountMap) == 0 {
		return nil
	}
	return accountMap
}

func GetAccountMap(multiAccount *MultiAccount) map[string]string {
	if multiAccount == nil {
		return nil
	}
	normalizedContent := normalizeMultiAccountContent(multiAccount.Content)
	if normalizedContent != "" {
		if len(multiAccount.AccountMap) > 0 && multiAccount.accountMapSource == normalizedContent {
			return multiAccount.AccountMap
		}
		if accountMap := parseMultiAccountContent(normalizedContent); len(accountMap) > 0 {
			return accountMap
		}
		return nil
	}
	if len(multiAccount.AccountMap) > 0 {
		return multiAccount.AccountMap
	}
	return nil
}

func CloneMultiAccountSnapshot(account *MultiAccount) *MultiAccount {
	return cloneMultiAccountSnapshot(account)
}

func cloneMultiAccountSnapshot(account *MultiAccount) *MultiAccount {
	if account == nil {
		return nil
	}
	cloned := &MultiAccount{
		Content:          normalizeMultiAccountContent(account.Content),
		accountMapSource: account.accountMapSource,
	}
	if accountMap := GetAccountMap(account); len(accountMap) > 0 {
		cloned.AccountMap = make(map[string]string, len(accountMap))
		for key, value := range accountMap {
			cloned.AccountMap[key] = value
		}
		if cloned.Content != "" {
			cloned.accountMapSource = cloned.Content
		}
	}
	return cloned
}
