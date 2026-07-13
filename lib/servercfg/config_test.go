package servercfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetTestState(t *testing.T) {
	t.Helper()
	mu.Lock()
	appConfig = nil
	appConfigPath = ""
	preferredPath = ""
	mu.Unlock()
	currentSnapshot.Store(defaultSnapshot)
}

func snapshotFormatRegistry() (map[string]parserFunc, map[string]string, []string) {
	mu.RLock()
	defer mu.RUnlock()

	parserCopy := make(map[string]parserFunc, len(parsers))
	for key, value := range parsers {
		parserCopy[key] = value
	}
	extensionCopy := make(map[string]string, len(extensionFormats))
	for key, value := range extensionFormats {
		extensionCopy[key] = value
	}
	return parserCopy, extensionCopy, append([]string(nil), extensionOrder...)
}

func restoreFormatRegistry(parsersSnapshot map[string]parserFunc, extensionSnapshot map[string]string, orderSnapshot []string) {
	mu.Lock()
	parsers = parsersSnapshot
	extensionFormats = extensionSnapshot
	extensionOrder = append([]string(nil), orderSnapshot...)
	mu.Unlock()
}

func writeConfig(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadINIValues(t *testing.T) {
	resetTestState(t)

	path := writeConfig(t, "nps.conf", "name=nps\nopen=true\nport=8080\nlarge=1234567890123\nempty=\nweb-base.url=/nps\ngeoip_path=conf/geoip.dat\ngeosite_path=conf/geosite.dat\nvisitor_vkey=visitor-demo\n")

	if err := Load(path); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got := Path(); got != path {
		t.Fatalf("Path() = %q, want %q", got, path)
	}
	if got := String("name"); got != "nps" {
		t.Fatalf("String(name) = %q, want nps", got)
	}
	if got := String("web_base_url"); got != "/nps" {
		t.Fatalf("String(web_base_url) = %q, want /nps", got)
	}
	if got := String("web.base-url"); got != "/nps" {
		t.Fatalf("String(web.base-url) = %q, want /nps", got)
	}
	if got := String("web-base_url"); got != "/nps" {
		t.Fatalf("String(web-base_url) = %q, want /nps", got)
	}
	cfg := Current()
	if cfg.Web.BaseURL != "/nps" {
		t.Fatalf("Current().Web.BaseURL = %q, want /nps", cfg.Web.BaseURL)
	}
	if cfg.App.GeoIPPath != "conf/geoip.dat" {
		t.Fatalf("Current().App.GeoIPPath = %q, want conf/geoip.dat", cfg.App.GeoIPPath)
	}
	if cfg.App.GeoSitePath != "conf/geosite.dat" {
		t.Fatalf("Current().App.GeoSitePath = %q, want conf/geosite.dat", cfg.App.GeoSitePath)
	}
	if cfg.Runtime.VisitorVKey != "visitor-demo" {
		t.Fatalf("Current().Runtime.VisitorVKey = %q, want visitor-demo", cfg.Runtime.VisitorVKey)
	}
	if got := String("missing"); got != "" {
		t.Fatalf("String(missing) = %q, want empty", got)
	}
	if got := DefaultString("empty", "fallback"); got != "fallback" {
		t.Fatalf("DefaultString(empty) = %q, want fallback", got)
	}
	if got := DefaultString("missing", "fallback"); got != "fallback" {
		t.Fatalf("DefaultString(missing) = %q, want fallback", got)
	}

	open, err := Bool("open")
	if err != nil || !open {
		t.Fatalf("Bool(open) = %v, %v, want true, nil", open, err)
	}

	port, err := Int("port")
	if err != nil || port != 8080 {
		t.Fatalf("Int(port) = %v, %v, want 8080, nil", port, err)
	}

	large, err := Int64("large")
	if err != nil || large != 1234567890123 {
		t.Fatalf("Int64(large) = %v, %v, want 1234567890123, nil", large, err)
	}
}

func TestLoadNormalizesWebBaseURL(t *testing.T) {
	testCases := []struct {
		name     string
		value    string
		expected string
	}{
		{name: "missing leading slash", value: "nps", expected: "/nps"},
		{name: "trailing slash", value: "/nps/", expected: "/nps"},
		{name: "extra slashes", value: " //nps//admin// ", expected: "/nps/admin"},
		{name: "root slash", value: "/", expected: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resetTestState(t)

			path := writeConfig(t, "nps.conf", "web_base_url="+tc.value+"\n")
			if err := Load(path); err != nil {
				t.Fatalf("Load() error = %v", err)
			}

			if got := String("web_base_url"); got != tc.expected {
				t.Fatalf("String(web_base_url) = %q, want %q", got, tc.expected)
			}
			if got := Current().Web.BaseURL; got != tc.expected {
				t.Fatalf("Current().Web.BaseURL = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestLoadLoginACLConfig(t *testing.T) {
	resetTestState(t)

	path := writeConfig(t, "nps.conf", strings.Join([]string{
		"login_acl_mode=1",
		"login_acl_rules=127.0.0.1,10.0.0.0/8,geoip:private",
	}, "\n")+"\n")

	if err := Load(path); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	cfg := Current()
	if cfg.Security.LoginACLMode != 1 {
		t.Fatalf("Current().Security.LoginACLMode = %d, want 1", cfg.Security.LoginACLMode)
	}
	if cfg.Security.LoginACLRules != "127.0.0.1,10.0.0.0/8,geoip:private" {
		t.Fatalf("Current().Security.LoginACLRules = %q", cfg.Security.LoginACLRules)
	}
}

func TestLoadYAMLNestedValues(t *testing.T) {
	resetTestState(t)

	path := writeConfig(t, "nps.yaml", "web:\n  port: 8081\n  open-ssl: false\n  base-url: /nps\np2p:\n  enable-birthday-attack: false\n  birthday_listen_ports: 32\n  enable_upnp_portmap: false\n")

	if err := Load(path); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	port, err := Int("web_port")
	if err != nil || port != 8081 {
		t.Fatalf("Int(web_port) = %v, %v, want 8081, nil", port, err)
	}
	openSSL, err := Bool("web.open_ssl")
	if err != nil || openSSL {
		t.Fatalf("Bool(web.open_ssl) = %v, %v, want false, nil", openSSL, err)
	}
	if got := String("web-base_url"); got != "/nps" {
		t.Fatalf("String(web-base_url) = %q, want /nps", got)
	}
	birthdayAttack, err := Bool("p2p_enable_birthday_attack")
	if err != nil || birthdayAttack {
		t.Fatalf("Bool(p2p_enable_birthday_attack) = %v, %v, want false, nil", birthdayAttack, err)
	}
	birthdayPorts, err := Int("p2p_birthday_listen_ports")
	if err != nil || birthdayPorts != 32 {
		t.Fatalf("Int(p2p_birthday_listen_ports) = %v, %v, want 32, nil", birthdayPorts, err)
	}
	cfg := Current()
	if cfg.Network.WebPort != 8081 {
		t.Fatalf("Current().Network.WebPort = %d, want 8081", cfg.Network.WebPort)
	}
	if cfg.P2P.EnableBirthdayAttack {
		t.Fatalf("Current().P2P.EnableBirthdayAttack = true, want false")
	}
	if cfg.P2P.BirthdayListenPorts != 32 {
		t.Fatalf("Current().P2P.BirthdayListenPorts = %d, want 32", cfg.P2P.BirthdayListenPorts)
	}
	if cfg.P2P.EnableUPNPPortmap {
		t.Fatalf("Current().P2P.EnableUPNPPortmap = true, want false")
	}
}

func TestLoadJSONNestedValues(t *testing.T) {
	resetTestState(t)

	path := writeConfig(t, "nps.json", "{\n  \"log\": {\"level\": \"debug\"},\n  \"bridge\": {\"tcp-port\": 8024},\n  \"system-info\": {\"display\": true}\n}\n")

	if err := Load(path); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got := String("log_level"); got != "debug" {
		t.Fatalf("String(log_level) = %q, want debug", got)
	}
	port, err := Int("bridge.tcp_port")
	if err != nil || port != 8024 {
		t.Fatalf("Int(bridge.tcp_port) = %v, %v, want 8024, nil", port, err)
	}
	infoDisplay, err := Bool("system-info.display")
	if err != nil || !infoDisplay {
		t.Fatalf("Bool(system-info.display) = %v, %v, want true, nil", infoDisplay, err)
	}
}

func TestLoadJSONNamespacedRuntimeAndProxyValues(t *testing.T) {
	resetTestState(t)

	path := writeConfig(t, "nps.json", `{
  "app": {"timezone": "Asia/Shanghai"},
  "auth": {"http_only_pass": "http-only-token", "allow_x_real_ip": true},
  "feature": {"allow_local_proxy": true},
  "runtime": {"flow_store_interval": 3},
  "security": {"secure_mode": true},
  "network": {"http_proxy_port": 18080},
  "proxy": {"error_page": "custom-error.html", "response_timeout": 17}
}`+"\n")

	if err := Load(path); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	cfg := Current()
	if cfg.App.Timezone != "Asia/Shanghai" {
		t.Fatalf("Current().App.Timezone = %q, want Asia/Shanghai", cfg.App.Timezone)
	}
	if cfg.Auth.HTTPOnlyPass != "http-only-token" {
		t.Fatalf("Current().Auth.HTTPOnlyPass = %q, want http-only-token", cfg.Auth.HTTPOnlyPass)
	}
	if !cfg.Auth.AllowXRealIP {
		t.Fatal("Current().Auth.AllowXRealIP = false, want true")
	}
	if !cfg.Feature.AllowLocalProxy {
		t.Fatal("Current().Feature.AllowLocalProxy = false, want true")
	}
	if cfg.Runtime.FlowStoreInterval != 3 {
		t.Fatalf("Current().Runtime.FlowStoreInterval = %d, want 3", cfg.Runtime.FlowStoreInterval)
	}
	if !cfg.Security.SecureMode {
		t.Fatal("Current().Security.SecureMode = false, want true")
	}
	if cfg.Network.HTTPProxyPort != 18080 {
		t.Fatalf("Current().Network.HTTPProxyPort = %d, want 18080", cfg.Network.HTTPProxyPort)
	}
	if cfg.Proxy.ErrorPage != "custom-error.html" {
		t.Fatalf("Current().Proxy.ErrorPage = %q, want custom-error.html", cfg.Proxy.ErrorPage)
	}
	if cfg.Proxy.ResponseTimeout != 17 {
		t.Fatalf("Current().Proxy.ResponseTimeout = %d, want 17", cfg.Proxy.ResponseTimeout)
	}
}

func TestDeviceEnrollmentConfigDefaultsOffAndCanBeEnabled(t *testing.T) {
	resetTestState(t)
	if Current().Feature.AllowDeviceEnrollment {
		t.Fatal("default AllowDeviceEnrollment = true, want false")
	}

	path := writeConfig(t, "nps.conf", "allow_device_enrollment=true\n")
	if err := Load(path); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !Current().Feature.AllowDeviceEnrollment {
		t.Fatal("AllowDeviceEnrollment = false, want true from config")
	}
}

func TestReload(t *testing.T) {
	resetTestState(t)

	path := writeConfig(t, "nps.conf", "name=before\n")

	if err := Load(path); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := String("name"); got != "before" {
		t.Fatalf("String(name) = %q, want before", got)
	}

	if err := os.WriteFile(path, []byte("name=after\n"), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	if err := Reload(); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if got := String("name"); got != "after" {
		t.Fatalf("String(name) = %q, want after", got)
	}
}

func TestDefaultPathsPreferExplicitFile(t *testing.T) {
	resetTestState(t)

	path := writeConfig(t, "nps.yaml", "web:\n  port: 8081\n")
	SetPreferredPath(path)

	paths := DefaultPaths()
	if len(paths) == 0 || paths[0] != path {
		t.Fatalf("DefaultPaths()[0] = %q, want %q", paths[0], path)
	}
}

func TestIsSupportedConfigPath(t *testing.T) {
	if !IsSupportedConfigPath("nps.conf") {
		t.Fatalf("nps.conf should be supported")
	}
	if !IsSupportedConfigPath("nps.yaml") {
		t.Fatalf("nps.yaml should be supported")
	}
	if !IsSupportedConfigPath("nps.json") {
		t.Fatalf("nps.json should be supported")
	}
	if IsSupportedConfigPath("nps.toml") {
		t.Fatalf("nps.toml should not be supported yet")
	}
}

func TestRegisterFormatRollbackOnFailure(t *testing.T) {
	parsersSnapshot, extensionSnapshot, orderSnapshot := snapshotFormatRegistry()
	t.Cleanup(func() {
		restoreFormatRegistry(parsersSnapshot, extensionSnapshot, orderSnapshot)
	})

	format := "unit-rollback"
	parser := func(path string) (map[string]any, error) {
		return map[string]any{"ok": true}, nil
	}
	if err := RegisterFormat(format, parser, ".unitrollback", ".json"); err == nil {
		t.Fatal("RegisterFormat() error = nil, want duplicate extension failure")
	}

	mu.RLock()
	_, formatRegistered := parsers[format]
	owner := extensionFormats[".unitrollback"]
	mu.RUnlock()
	if formatRegistered {
		t.Fatalf("RegisterFormat() should not retain failed parser registration for %q", format)
	}
	if owner != "" {
		t.Fatalf("RegisterFormat() should not retain leaked extension ownership, got %q", owner)
	}
	if IsSupportedConfigPath("nps.unitrollback") {
		t.Fatal("IsSupportedConfigPath(nps.unitrollback) = true, want false after failed registration")
	}

	if err := RegisterFormat(format, parser, ".unitrollback"); err != nil {
		t.Fatalf("RegisterFormat() retry error = %v", err)
	}
	if !IsSupportedConfigPath("nps.unitrollback") {
		t.Fatal("IsSupportedConfigPath(nps.unitrollback) = false, want true after successful retry")
	}
}

func TestRegisterFormatRejectsDuplicateExtensionsInSingleCall(t *testing.T) {
	parsersSnapshot, extensionSnapshot, orderSnapshot := snapshotFormatRegistry()
	t.Cleanup(func() {
		restoreFormatRegistry(parsersSnapshot, extensionSnapshot, orderSnapshot)
	})

	err := RegisterFormat("unit-duplicate", func(path string) (map[string]any, error) {
		return nil, nil
	}, ".unitdup", "unitdup")
	if err == nil {
		t.Fatal("RegisterFormat() error = nil, want duplicate extension failure")
	}
	if IsSupportedConfigPath("nps.unitdup") {
		t.Fatal("IsSupportedConfigPath(nps.unitdup) = true, want false after duplicate extension failure")
	}
}
