package servercfg

import (
	"strings"

	"github.com/djylb/nps/lib/p2p"
)

func namespacedKeys(namespace string, keys ...string) []string {
	seen := make(map[string]struct{}, len(keys)*2)
	aliases := make([]string, 0, len(keys)*2)
	appendKey := func(key string) {
		normalized := normalizeKey(key)
		if normalized == "" {
			return
		}
		if _, exists := seen[normalized]; exists {
			return
		}
		seen[normalized] = struct{}{}
		aliases = append(aliases, key)
	}
	for _, key := range keys {
		appendKey(key)
		if namespace != "" {
			appendKey(joinKey(namespace, key))
		}
	}
	return aliases
}

func buildRuntimeConfig(r valueReader) RuntimeConfig {
	nodeTrafficReportInterval := -1
	if value, ok := r.intValue(namespacedKeys("runtime", "node_traffic_report_interval_seconds")...); ok {
		nodeTrafficReportInterval = value
	}
	nodeTrafficReportStep := int64(-1)
	if value, ok := r.int64Value(namespacedKeys("runtime", "node_traffic_report_step_bytes")...); ok {
		nodeTrafficReportStep = value
	}

	cfg := RuntimeConfig{
		RunMode:                   strings.ToLower(strings.TrimSpace(r.stringDefault("standalone", namespacedKeys("runtime", "run_mode")...))),
		MasterURL:                 r.stringValue(namespacedKeys("runtime", "master_url")...),
		NodeToken:                 r.stringValue(namespacedKeys("runtime", "node_token")...),
		ManagementPlatforms:       parseManagementPlatforms(r),
		PublicVKey:                r.stringValue(namespacedKeys("runtime", "public_vkey")...),
		VisitorVKey:               r.stringValue(namespacedKeys("runtime", "visitor_vkey")...),
		IPLimit:                   r.stringValue(namespacedKeys("runtime", "ip_limit")...),
		DisconnectTimeout:         r.intDefault(30, namespacedKeys("runtime", "disconnect_timeout")...),
		FlowStoreInterval:         r.intDefault(0, namespacedKeys("runtime", "flow_store_interval")...),
		NodeEventLogSize:          r.intDefault(1024, namespacedKeys("runtime", "node_changes_window", "node_event_log_size")...),
		NodeBatchMaxItems:         r.intDefault(50, namespacedKeys("runtime", "node_batch_max_items")...),
		NodeIdempotencyTTL:        r.intDefault(300, namespacedKeys("runtime", "node_idempotency_ttl_seconds")...),
		NodeTrafficReportInterval: nodeTrafficReportInterval,
		NodeTrafficReportStep:     nodeTrafficReportStep,
	}
	if cfg.RunMode == "" {
		cfg.RunMode = "standalone"
	}
	if len(cfg.ManagementPlatforms) == 0 && strings.TrimSpace(cfg.NodeToken) != "" {
		cfg.ManagementPlatforms = normalizeManagementPlatforms([]ManagementPlatformConfig{{
			PlatformID:      "legacy-master",
			Token:           strings.TrimSpace(cfg.NodeToken),
			ControlScope:    "full",
			Enabled:         true,
			ServiceUsername: defaultPlatformServiceUsername("legacy-master"),
			MasterURL:       strings.TrimSpace(cfg.MasterURL),
		}})
	}
	if len(cfg.ManagementPlatforms) > 0 && strings.TrimSpace(cfg.NodeToken) == "" {
		cfg.NodeToken = cfg.ManagementPlatforms[0].Token
	}
	return cfg
}

func buildP2PConfig(r valueReader) P2PConfig {
	return P2PConfig{
		ProbeExtraReply:           r.boolDefault(true, "p2p_probe_extra_reply"),
		ForcePredictOnRestricted:  r.boolDefault(true, "p2p_force_predict_on_restricted"),
		EnableTargetSpray:         r.boolDefault(true, "p2p_enable_target_spray"),
		EnableBirthdayAttack:      r.boolDefault(true, "p2p_enable_birthday_attack"),
		EnableUPNPPortmap:         r.boolDefault(true, "p2p_enable_upnp_portmap"),
		EnablePCPPortmap:          r.boolDefault(true, "p2p_enable_pcp_portmap"),
		EnableNATPMPPortmap:       r.boolDefault(true, "p2p_enable_natpmp_portmap"),
		PortmapLeaseSeconds:       r.intDefault(3600, "p2p_portmap_lease_seconds"),
		DefaultPredictionInterval: r.intDefault(p2p.DefaultPredictionInterval, "p2p_default_prediction_interval"),
		TargetSpraySpan:           r.intDefault(p2p.DefaultSpraySpan, "p2p_target_spray_span"),
		TargetSprayRounds:         r.intDefault(p2p.DefaultSprayRounds, "p2p_target_spray_rounds"),
		TargetSprayBurst:          r.intDefault(p2p.DefaultSprayBurst, "p2p_target_spray_burst"),
		TargetSprayPacketSleepMs:  r.intDefault(3, "p2p_target_spray_packet_sleep_ms"),
		TargetSprayBurstGapMs:     r.intDefault(10, "p2p_target_spray_burst_gap_ms"),
		TargetSprayPhaseGapMs:     r.intDefault(40, "p2p_target_spray_phase_gap_ms"),
		BirthdayListenPorts:       r.intDefault(p2p.DefaultBirthdayPorts, "p2p_birthday_listen_ports"),
		BirthdayTargetsPerPort:    r.intDefault(p2p.DefaultBirthdayTargets, "p2p_birthday_targets_per_port"),
		ProbeTimeoutMs:            r.intDefault(5000, "p2p_probe_timeout_ms"),
		HandshakeTimeoutMs:        r.intDefault(20000, "p2p_handshake_timeout_ms"),
		TransportTimeoutMs:        r.intDefault(10000, "p2p_transport_timeout_ms"),
	}
}

func buildAppConfig(r valueReader) AppConfig {
	return AppConfig{
		Name:        r.stringDefault("nps", "appname", "app_name"),
		Timezone:    r.stringValue(namespacedKeys("app", "timezone")...),
		DNSServer:   r.stringValue(namespacedKeys("app", "dns_server")...),
		GeoIPPath:   r.stringValue(namespacedKeys("app", "geoip_path")...),
		GeoSitePath: r.stringValue(namespacedKeys("app", "geosite_path")...),
		PprofIP:     r.stringValue(namespacedKeys("app", "pprof_ip")...),
		PprofPort:   r.stringDefault("0", namespacedKeys("app", "pprof_port")...),
		NTPServer:   r.stringValue(namespacedKeys("app", "ntp_server")...),
		NTPInterval: r.intDefault(5, namespacedKeys("app", "ntp_interval")...),
	}
}

func buildLogConfig(r valueReader) LogConfig {
	return LogConfig{
		Type:     r.stringDefault("stdout", "log"),
		Level:    r.stringDefault("trace", "log_level"),
		Path:     r.stringValue("log_path"),
		MaxFiles: r.intDefault(30, "log_max_files"),
		MaxDays:  r.intDefault(30, "log_max_days"),
		MaxSize:  r.intDefault(5, "log_max_size"),
		Compress: r.boolDefault(false, "log_compress"),
		Color:    r.boolDefault(true, "log_color"),
	}
}

func buildWebConfig(r valueReader) WebConfig {
	return WebConfig{
		BaseURL:                    normalizeBaseURL(r.stringValue("web_base_url")),
		HeadCustomCode:             r.stringValue("head_custom_code"),
		Host:                       r.stringValue("web_host"),
		IP:                         r.stringDefault("0.0.0.0", "web_ip"),
		Port:                       r.intDefault(0, "web_port"),
		OpenSSL:                    r.boolDefault(false, "web_open_ssl"),
		CloseOnNotFound:            r.boolDefault(false, "web_close_on_not_found"),
		KeyFile:                    r.stringValue("web_key_file"),
		CertFile:                   r.stringValue("web_cert_file"),
		Username:                   r.stringValue("web_username"),
		Password:                   r.stringValue("web_password"),
		TOTPSecret:                 r.stringValue("totp_secret", "web_totp_secret"),
		StandaloneAllowedOrigins:   r.stringValue("web_standalone_allowed_origins", "standalone_allowed_origins"),
		StandaloneAllowCredentials: r.boolDefault(false, "web_standalone_allow_credentials", "standalone_allow_credentials"),
		StandaloneTokenSecret:      r.stringValue("web_standalone_token_secret", "standalone_token_secret"),
		StandaloneTokenTTLSeconds:  r.int64Default(0, "web_standalone_token_ttl_seconds", "standalone_token_ttl_seconds"),
	}
}

func buildAuthConfig(r valueReader) AuthConfig {
	return AuthConfig{
		Key:             r.stringValue("auth_key"),
		CryptKey:        r.stringValue("auth_crypt_key"),
		HTTPOnlyPass:    r.stringValue("x_nps_http_only", "http_only_pass", "auth_http_only_pass"),
		AllowXRealIP:    r.boolDefault(false, "allow_x_real_ip", "auth_allow_x_real_ip"),
		TrustedProxyIPs: r.stringDefault("127.0.0.1", "trusted_proxy_ips", "auth_trusted_proxy_ips"),
	}
}

func buildFeatureConfig(r valueReader) FeatureConfig {
	cfg := FeatureConfig{
		AllowUserLogin:          r.boolDefault(false, namespacedKeys("feature", "allow_user_login")...),
		AllowUserRegister:       r.boolDefault(false, namespacedKeys("feature", "allow_user_register")...),
		AllowUserChangeUsername: r.boolDefault(false, namespacedKeys("feature", "allow_user_change_username")...),
		OpenCaptcha:             r.boolDefault(false, namespacedKeys("feature", "open_captcha")...),
		AllowFlowLimit:          r.boolDefault(false, namespacedKeys("feature", "allow_flow_limit")...),
		AllowRateLimit:          r.boolDefault(false, namespacedKeys("feature", "allow_rate_limit")...),
		AllowTimeLimit:          r.boolDefault(false, namespacedKeys("feature", "allow_time_limit")...),
		AllowConnectionNumLimit: r.boolDefault(false, namespacedKeys("feature", "allow_connection_num_limit")...),
		AllowMultiIP:            r.boolDefault(false, namespacedKeys("feature", "allow_multi_ip")...),
		AllowTunnelNumLimit:     r.boolDefault(false, namespacedKeys("feature", "allow_tunnel_num_limit")...),
		AllowLocalProxy:         r.boolDefault(false, namespacedKeys("feature", "allow_local_proxy")...),
		AllowSecretLocal:        r.boolDefault(false, namespacedKeys("feature", "allow_secret_local")...),
		AllowDeviceEnrollment:   r.boolDefault(false, namespacedKeys("feature", "allow_device_enrollment", "device_enrollment")...),
		SystemInfoDisplay:       r.boolDefault(false, namespacedKeys("feature", "system_info_display")...),
		AllowPorts:              r.stringValue(namespacedKeys("feature", "allow_ports")...),
	}
	cfg.AllowUserLocal = r.boolDefault(cfg.AllowLocalProxy, namespacedKeys("feature", "allow_user_local")...)
	cfg.AllowUserVkeyLogin = r.boolDefault(cfg.AllowUserLogin, namespacedKeys("feature", "allow_user_vkey_login")...)
	return cfg
}

func buildSecurityConfig(r valueReader) SecurityConfig {
	return SecurityConfig{
		SecureMode:        r.boolDefault(false, namespacedKeys("security", "secure_mode")...),
		ForcePoW:          r.boolDefault(false, namespacedKeys("security", "force_pow")...),
		PoWBits:           r.intDefault(20, namespacedKeys("security", "pow_bits")...),
		LoginBanTime:      r.int64Default(5, namespacedKeys("security", "login_ban_time")...),
		LoginIPBanTime:    r.int64Default(180, namespacedKeys("security", "login_ip_ban_time")...),
		LoginUserBanTime:  r.int64Default(3600, namespacedKeys("security", "login_user_ban_time")...),
		LoginMaxFailTimes: r.intDefault(10, namespacedKeys("security", "login_max_fail_times")...),
		LoginMaxBody:      r.int64Default(1024, namespacedKeys("security", "login_max_body")...),
		LoginMaxSkew:      r.int64Default(5*60*1000, namespacedKeys("security", "login_max_skew")...),
		LoginACLMode:      r.intDefault(0, namespacedKeys("security", "login_acl_mode")...),
		LoginACLRules:     r.stringValue(namespacedKeys("security", "login_acl_rules")...),
	}
}

func buildNetworkConfig(r valueReader, web WebConfig) NetworkConfig {
	cfg := NetworkConfig{}
	cfg.BridgeIP = r.stringDefault(r.stringDefault("0.0.0.0", namespacedKeys("network", "bridge_tcp_ip")...), namespacedKeys("network", "bridge_ip")...)
	cfg.BridgeHost = r.stringValue(namespacedKeys("network", "bridge_host")...)
	cfg.BridgeTCPIP = r.stringDefault(cfg.BridgeIP, namespacedKeys("network", "bridge_tcp_ip")...)
	cfg.BridgeKCPIP = r.stringDefault(cfg.BridgeIP, namespacedKeys("network", "bridge_kcp_ip")...)
	cfg.BridgeQUICIP = r.stringDefault(cfg.BridgeIP, namespacedKeys("network", "bridge_quic_ip")...)
	cfg.BridgeTLSIP = r.stringDefault(cfg.BridgeIP, namespacedKeys("network", "bridge_tls_ip")...)
	cfg.BridgeWSIP = r.stringDefault(cfg.BridgeIP, namespacedKeys("network", "bridge_ws_ip")...)
	cfg.BridgeWSSIP = r.stringDefault(cfg.BridgeIP, namespacedKeys("network", "bridge_wss_ip")...)
	cfg.BridgePort = r.intDefault(r.intDefault(0, namespacedKeys("network", "bridge_tcp_port")...), namespacedKeys("network", "bridge_port")...)
	cfg.BridgeTCPPort = r.intDefault(cfg.BridgePort, namespacedKeys("network", "bridge_tcp_port")...)
	cfg.BridgeKCPPort = r.intDefault(cfg.BridgePort, namespacedKeys("network", "bridge_kcp_port")...)
	cfg.BridgeQUICPort = r.intDefault(0, namespacedKeys("network", "bridge_quic_port")...)
	cfg.BridgeTLSPort = r.intDefault(r.intDefault(0, namespacedKeys("network", "tls_bridge_port")...), namespacedKeys("network", "bridge_tls_port")...)
	cfg.BridgeWSPort = r.intDefault(0, namespacedKeys("network", "bridge_ws_port")...)
	cfg.BridgeWSSPort = r.intDefault(0, namespacedKeys("network", "bridge_wss_port")...)
	cfg.BridgePath = r.stringDefault("/ws", namespacedKeys("network", "bridge_path")...)
	cfg.BridgeTrustedIPs = r.stringValue(namespacedKeys("network", "bridge_trusted_ips")...)
	cfg.BridgeRealIPHeader = r.stringValue(namespacedKeys("network", "bridge_real_ip_header")...)
	cfg.HTTPProxyIP = r.stringDefault("0.0.0.0", namespacedKeys("network", "http_proxy_ip")...)
	cfg.HTTPProxyPort = r.intDefault(0, namespacedKeys("network", "http_proxy_port")...)
	cfg.HTTPSProxyPort = r.intDefault(0, namespacedKeys("network", "https_proxy_port")...)
	cfg.HTTP3ProxyPort = r.intDefault(cfg.HTTPSProxyPort, namespacedKeys("network", "http3_proxy_port")...)
	cfg.WebIP = web.IP
	cfg.WebPort = web.Port
	cfg.P2PIP = r.stringDefault("0.0.0.0", namespacedKeys("network", "p2p_ip")...)
	cfg.P2PPort = r.intDefault(0, namespacedKeys("network", "p2p_port")...)
	cfg.QUICALPN = r.stringDefault("nps", namespacedKeys("network", "quic_alpn")...)
	cfg.QUICALPNList = splitAndTrimCSV(cfg.QUICALPN)
	if len(cfg.QUICALPNList) == 0 {
		cfg.QUICALPNList = []string{"nps"}
	}
	cfg.QUICKeepAlivePeriod = r.intDefault(10, namespacedKeys("network", "quic_keep_alive_period")...)
	cfg.QUICMaxIdleTimeout = r.intDefault(30, namespacedKeys("network", "quic_max_idle_timeout")...)
	cfg.QUICMaxIncomingStreams = r.int64Default(100000, namespacedKeys("network", "quic_max_incoming_streams")...)
	cfg.MuxPingInterval = r.intDefault(5, namespacedKeys("network", "mux_ping_interval")...)
	return cfg
}

func buildBridgeConfig(r valueReader, network NetworkConfig) BridgeConfig {
	cfg := BridgeConfig{
		Addr:       r.stringValue("bridge_addr"),
		Type:       strings.ToLower(strings.TrimSpace(r.stringDefault("both", "bridge_type"))),
		SelectMode: r.stringValue("bridge_select_mode"),
		CertFile:   r.stringValue("bridge_cert_file"),
		KeyFile:    r.stringValue("bridge_key_file"),
		TCPEnable:  r.boolDefault(true, "tcp_enable", "bridge_tcp_enable"),
		KCPEnable:  r.boolDefault(true, "kcp_enable", "bridge_kcp_enable"),
		QUICEnable: r.boolDefault(true, "quic_enable", "bridge_quic_enable"),
		TLSEnable:  r.boolDefault(true, "tls_enable", "bridge_tls_enable"),
		WSEnable:   r.boolDefault(true, "ws_enable", "bridge_ws_enable"),
		WSSEnable:  r.boolDefault(true, "wss_enable", "bridge_wss_enable"),
	}
	if cfg.Type == "" {
		cfg.Type = "both"
	}
	cfg.PrimaryType = cfg.Type
	if cfg.PrimaryType == "both" {
		cfg.PrimaryType = "tcp"
	}
	cfg.ServerKCPEnabled = cfg.KCPEnable && network.BridgeKCPPort != 0 && (cfg.Type == "kcp" || cfg.Type == "udp" || cfg.Type == "both")
	cfg.ServerQUICEnabled = cfg.QUICEnable && network.BridgeQUICPort != 0 && (cfg.Type == "quic" || cfg.Type == "udp" || cfg.Type == "both")
	cfg.ServerTCPEnabled = cfg.TCPEnable && network.BridgeTCPPort != 0 && cfg.PrimaryType == "tcp"
	cfg.ServerTLSEnabled = cfg.TLSEnable && network.BridgeTLSPort != 0 && cfg.PrimaryType == "tcp"
	cfg.ServerWSEnabled = cfg.WSEnable && network.BridgeWSPort != 0 && network.BridgePath != "" && cfg.PrimaryType == "tcp"
	cfg.ServerWSSEnabled = cfg.WSSEnable && network.BridgeWSSPort != 0 && network.BridgePath != "" && cfg.PrimaryType == "tcp"
	cfg.Display = BridgeDisplayConfig{
		Path: r.stringDefault(network.BridgePath, "bridge_show_path"),
		TCP: BridgeDisplayEndpoint{
			Show: r.boolDefault(cfg.ServerTCPEnabled, "bridge_tcp_show"),
			IP:   r.stringValue("bridge_tcp_show_ip"),
			Port: r.stringDefault(portString(network.BridgeTCPPort), "bridge_tcp_show_port"),
		},
		KCP: BridgeDisplayEndpoint{
			Show: r.boolDefault(cfg.ServerKCPEnabled, "bridge_kcp_show"),
			IP:   r.stringValue("bridge_kcp_show_ip"),
			Port: r.stringDefault(portString(network.BridgeKCPPort), "bridge_kcp_show_port"),
		},
		QUIC: BridgeDisplayEndpoint{
			Show: r.boolDefault(cfg.ServerQUICEnabled, "bridge_quic_show"),
			IP:   r.stringValue("bridge_quic_show_ip"),
			Port: r.stringDefault(portString(network.BridgeQUICPort), "bridge_quic_show_port"),
			ALPN: r.stringDefault(network.QUICALPNList[0], "bridge_quic_show_alpn"),
		},
		TLS: BridgeDisplayEndpoint{
			Show: r.boolDefault(cfg.ServerTLSEnabled, "bridge_tls_show"),
			IP:   r.stringValue("bridge_tls_show_ip"),
			Port: r.stringDefault(portString(network.BridgeTLSPort), "bridge_tls_show_port"),
		},
		WS: BridgeDisplayEndpoint{
			Show: r.boolDefault(cfg.ServerWSEnabled, "bridge_ws_show"),
			IP:   r.stringValue("bridge_ws_show_ip"),
			Port: r.stringDefault(portString(network.BridgeWSPort), "bridge_ws_show_port"),
		},
		WSS: BridgeDisplayEndpoint{
			Show: r.boolDefault(cfg.ServerWSSEnabled, "bridge_wss_show"),
			IP:   r.stringValue("bridge_wss_show_ip"),
			Port: r.stringDefault(portString(network.BridgeWSSPort), "bridge_wss_show_port"),
		},
	}
	return cfg
}

func buildProxyConfig(r valueReader) ProxyConfig {
	return ProxyConfig{
		AddOriginHeader:    r.boolDefault(false, "http_add_origin_header", "proxy_add_origin_header"),
		ResponseTimeout:    r.intDefault(100, "http_proxy_response_timeout", "proxy_response_timeout"),
		ErrorPage:          r.stringDefault("web/static/page/error.html", "error_page", "proxy_error_page"),
		ErrorPageTimeLimit: r.stringValue("error_page_time_limit", "proxy_error_page_time_limit"),
		ErrorPageFlowLimit: r.stringValue("error_page_flow_limit", "proxy_error_page_flow_limit"),
		ErrorAlways:        r.boolDefault(false, "error_always", "proxy_error_always"),
		BridgeHTTP3:        r.boolDefault(true, "bridge_http3", "proxy_bridge_http3"),
		ForceAutoSSL:       r.boolDefault(false, "force_auto_ssl", "proxy_force_auto_ssl"),
		SSL: SSLConfig{
			Email:           r.stringValue("ssl_email", "proxy_ssl_email"),
			CA:              r.stringDefault("LetsEncrypt", "ssl_ca", "proxy_ssl_ca"),
			Path:            r.stringDefault("ssl", "ssl_path", "proxy_ssl_path"),
			ZeroSSLAPI:      r.stringValue("ssl_zerossl_api", "proxy_ssl_zerossl_api"),
			DefaultCertFile: r.stringValue("https_default_cert_file", "proxy_ssl_default_cert_file"),
			DefaultKeyFile:  r.stringValue("https_default_key_file", "proxy_ssl_default_key_file"),
			CacheMax:        r.intDefault(0, "ssl_cache_max", "proxy_ssl_cache_max"),
			CacheReload:     r.intDefault(0, "ssl_cache_reload", "proxy_ssl_cache_reload"),
			CacheIdle:       r.intDefault(60, "ssl_cache_idle", "proxy_ssl_cache_idle"),
		},
	}
}
