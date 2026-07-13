//go:build !sdk

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/djylb/nps/client"
	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/install"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/mux"
	"github.com/djylb/nps/lib/version"
	"github.com/kardianos/service"
)

func parsePrimaryCommand(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func handleImmediateFlags() bool {
	if *genTOTP {
		crypt.PrintTOTPSecret()
		return true
	}
	if *getTOTP != "" {
		crypt.PrintTOTPCode(*getTOTP)
		return true
	}
	if *ver {
		version.PrintVersion(*protoVer)
		return true
	}
	return false
}

func prepareNPCStartup(cmd string) {
	resolveNPCLaunch(cmd)
	applyNPCGlobalFlags()
	configureNPCRuntimeEnvironment()
}

func resolveNPCLaunch(cmd string) {
	if !commandNeedsLaunchResolution(cmd) {
		return
	}
	if err := resolveLaunchFlags(); err != nil {
		switch cmd {
		case "status", "register":
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		default:
			launchResolveErr = err
		}
	}
}

func applyNPCGlobalFlags() {
	client.Ver = *protoVer
	client.SkipTLSVerify = *skipVerify
	client.DisableP2P = *disableP2P
	client.AutoReconnect = *autoReconnect
	client.LocalIPForward = *localIPForward
	crypt.SkipVerify = *skipVerify
	if *protoVer < 2 {
		crypt.SkipVerify = true
	}
}

func configureNPCRuntimeEnvironment() {
	if err := common.SetTimezone(*timezone); err != nil {
		logs.Warn("Set timezone error %v", err)
	}
	configureLogging()
	common.SetCustomDNS(*dnsServer)
	common.SetNtpServer(*ntpServer)
	common.SetNtpInterval(time.Duration(*ntpInterval) * time.Minute)
	applyNPCKeepAlive()
	applyNPCP2PMode()
}

func applyNPCKeepAlive() {
	if *keepAlive <= 0 {
		return
	}
	interval := time.Duration(*keepAlive) * time.Second
	client.QuicConfig.KeepAlivePeriod = interval
	mux.PingInterval = interval
}

func applyNPCP2PMode() {
	switch strings.ToLower(*p2pType) {
	case common.CONN_QUIC:
		client.P2PMode = common.CONN_QUIC
	case common.CONN_KCP:
		client.P2PMode = common.CONN_KCP
	}
}

func buildNPCServiceConfig(args []string) *service.Config {
	options := make(service.KeyValue)
	svcConfig := &service.Config{
		Name:        "Npc",
		DisplayName: "nps内网穿透客户端",
		Description: "一款轻量级、功能强大的内网穿透代理服务器。支持tcp、udp流量转发，支持内网http代理、内网socks5代理，同时支持snappy压缩、站点保护、加密传输、多路复用、header修改等。支持web图形化管理，集成多用户模式。",
		Option:      options,
	}
	if !common.IsWindows() {
		svcConfig.Dependencies = []string{
			"Requires=network.target",
			"After=network-online.target syslog.target",
		}
		svcConfig.Option["SystemdScript"] = install.SystemdScript
		svcConfig.Option["SysvScript"] = install.SysvScript
	}
	for _, arg := range args {
		switch arg {
		case "install", "start", "stop", "uninstall", "restart", "status", "register", "update":
			continue
		}
		if !strings.Contains(arg, "-service=") && !strings.Contains(arg, "-debug=") {
			svcConfig.Arguments = append(svcConfig.Arguments, arg)
		}
	}
	svcConfig.Arguments = append(svcConfig.Arguments, "-debug=false")
	return svcConfig
}

func handleNPCServiceCommand(ctx context.Context, cancel context.CancelFunc, cmd string, svc service.Service, svcConfig *service.Config) bool {
	switch cmd {
	case "status":
		server, vkey, tp, proxy, ip, err := launchCommandArgs()
		if err != nil {
			logs.Error("%v", err)
			os.Exit(1)
		}
		statuses, err := client.GetTaskStatus(server, vkey, tp, proxy, ip)
		if err != nil {
			logs.Error("%v", err)
			os.Exit(1)
		}
		fmt.Print(client.FormatTaskStatus(statuses))
		return true
	case "register":
		server, vkey, tp, proxy, ip, err := launchCommandArgs()
		if err != nil {
			logs.Error("%v", err)
			os.Exit(1)
		}
		if err := client.RegisterLocalIp(server, vkey, tp, proxy, ip, *registerTime); err != nil {
			logs.Error("%v", err)
			os.Exit(1)
		}
		logs.Info("Successful ip registration for local public network, the validity period is %d hours.", *registerTime)
		return true
	case "update":
		if err := install.UpdateNpc(); err != nil {
			logs.Error("%v", err)
		}
		return true
	case "start", "stop", "restart":
		if service.Platform() == "unix-systemv" {
			logs.Info("unix-systemv service")
			command := exec.Command("/etc/init.d/"+svcConfig.Name, cmd)
			if err := command.Run(); err != nil {
				logs.Error("%v", err)
			}
			return true
		}
		if err := service.Control(svc, cmd); err != nil {
			logs.Error("Valid actions: %q error: %v", service.ControlAction, err)
		}
		return true
	case "install":
		_ = service.Control(svc, "stop")
		_ = service.Control(svc, "uninstall")
		if err := install.NPC(); err != nil {
			logs.Error("%v", err)
			return true
		}
		if err := service.Control(svc, cmd); err != nil {
			logs.Error("Valid actions: %q error: %v", service.ControlAction, err)
		}
		if service.Platform() == "unix-systemv" {
			logs.Info("unix-systemv service")
			confPath := "/etc/init.d/" + svcConfig.Name
			_ = os.Symlink(confPath, "/etc/rc.d/S90"+svcConfig.Name)
			_ = os.Symlink(confPath, "/etc/rc.d/K02"+svcConfig.Name)
		}
		return true
	case "uninstall":
		if err := service.Control(svc, cmd); err != nil {
			logs.Error("Valid actions: %q error: %v", service.ControlAction, err)
		}
		if service.Platform() == "unix-systemv" {
			logs.Info("unix-systemv service")
			_ = os.Remove("/etc/rc.d/S90" + svcConfig.Name)
			_ = os.Remove("/etc/rc.d/K02" + svcConfig.Name)
		}
		return true
	default:
		_ = ctx
		_ = cancel
		return false
	}
}

var npcStartFromFile = client.StartFromFile

// Log configure
func configureLogging() {
	if strings.EqualFold(*logType, "false") {
		*logType = "off"
	}
	if *debug && *logType != "off" {
		if *logType != "both" {
			*logType = "stdout"
		}
		*logLevel = "trace"
	}
	if *logPath == "" || strings.EqualFold(*logPath, "on") || strings.EqualFold(*logPath, "true") {
		*logPath = common.GetNpcLogPath()
	}
	if !filepath.IsAbs(*logPath) {
		*logPath = filepath.Join(common.GetRunPath(), *logPath)
	}
	if common.IsWindows() {
		*logPath = strings.ReplaceAll(*logPath, "\\", "\\\\")
	}
	logs.Init(*logType, *logLevel, *logPath, *logMaxSize, *logMaxFiles, *logMaxDays, *logCompress, *logColor)
}

type Npc struct {
	ctx    context.Context
	cancel context.CancelFunc
	exit   chan struct{}
	exitMu sync.Once
	stopMu sync.Once
}

func NewNpc(pCtx context.Context) *Npc {
	ctx, cancel := context.WithCancel(pCtx)
	return &Npc{
		ctx:    ctx,
		exit:   make(chan struct{}),
		cancel: cancel,
	}
}

func (p *Npc) Start(_ service.Service) error {
	p.exitChan()
	go func() { _ = p.run() }()
	return nil
}

func (p *Npc) Stop(_ service.Service) error {
	p.signalExit()
	if p != nil && p.cancel != nil {
		p.cancel()
	}
	if npcServiceInteractive() {
		os.Exit(0)
	}
	return nil
}

func (p *Npc) run() error {
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			logs.Warn("npc: panic serving %v: %s", err, buf)
		}
	}()
	run(p.ctx, p.cancel)
	<-p.exitChan()
	logs.Warn("stop...")
	return nil
}

var npcServiceInteractive = service.Interactive

func (p *Npc) exitChan() chan struct{} {
	if p == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	p.exitMu.Do(func() {
		if p.exit == nil {
			p.exit = make(chan struct{})
		}
	})
	return p.exit
}

func (p *Npc) signalExit() {
	if p == nil {
		return
	}
	ch := p.exitChan()
	p.stopMu.Do(func() {
		close(ch)
	})
}

// 主运行逻辑
func run(ctx context.Context, cancel context.CancelFunc) {
	common.InitPProfByAddr(*pprofAddr)
	applyLegacyTLSModeFlag()
	if handled := runExplicitLocalLaunch(ctx, cancel); handled {
		return
	}
	if handled := runLaunchPayloadMode(ctx, cancel); handled {
		return
	}
	hasCommand := applyLegacyEnvironmentDefaults()
	if shouldTryZeroTouch(hasCommand) {
		if handled := runZeroTouchMode(ctx, cancel); handled {
			return
		}
	}
	runLegacyCommandAndConfig(ctx, cancel, hasCommand)
}

func applyLegacyTLSModeFlag() {
	if *tlsEnable {
		*connType = "tls"
	}
}

func runExplicitLocalLaunch(ctx context.Context, cancel context.CancelFunc) bool {
	if *password == "" {
		return false
	}
	if err := startLaunchLocal(ctx, cancel, &client.LaunchLocal{
		Server:         *serverAddr,
		VKey:           *verifyKey,
		Type:           *connType,
		Proxy:          *proxyUrl,
		LocalIP:        *localIP,
		LocalType:      *localType,
		LocalPort:      localPort,
		Password:       *password,
		Target:         *target,
		TargetType:     *targetType,
		FallbackSecret: fallbackSecret,
		LocalProxy:     localProxy,
	}); err != nil {
		logs.Error("Start local launch error %v", err)
		os.Exit(1)
	}
	return true
}

func runLaunchPayloadMode(ctx context.Context, cancel context.CancelFunc) bool {
	inputs := currentLaunchInputs()
	if len(inputs) == 0 || hasExplicitLegacyModeFlags() {
		return false
	}
	if launchResolveErr != nil {
		logs.Warn("Initial launch resolution failed, background supervisor will keep retrying: %v", launchResolveErr)
	}
	if err := startLaunchInputs(ctx, cancel, inputs, resolvedLaunchRuntime()); err != nil {
		logs.Error("Start launch payload error %v", err)
		os.Exit(1)
	}
	return true
}

func applyLegacyEnvironmentDefaults() bool {
	env := common.GetEnvMap()
	if *serverAddr == "" {
		*serverAddr = env["NPC_SERVER_ADDR"]
	}
	if *verifyKey == "" {
		*verifyKey = env["NPC_SERVER_VKEY"]
	}
	if *configPath == "" {
		*configPath = env["NPC_CONFIG_PATH"]
	}
	if *localIP == "" {
		*localIP = env["NPC_LOCAL_IP"]
	}
	return *verifyKey != "" && *serverAddr != ""
}

func runLegacyCommandAndConfig(ctx context.Context, cancel context.CancelFunc, hasCommand bool) {
	if hasCommand {
		if err := startLaunchDirect(ctx, cancel, *serverAddr, *verifyKey, *connType, *proxyUrl, *localIP); err != nil {
			logs.Error("%v", err)
			os.Exit(1)
		}
	}
	if *configPath != "" || !hasCommand {
		startFromConfigFiles(ctx, cancel)
	}
}

func startFromConfigFiles(ctx context.Context, cancel context.CancelFunc) {
	if *configPath == "" {
		*configPath = common.GetConfigPath()
	}
	configPaths := strings.Split(*configPath, ",")
	for i := range configPaths {
		configPaths[i] = strings.TrimSpace(configPaths[i])
	}
	for _, path := range configPaths {
		path := path
		if path == "" {
			continue
		}
		go func() {
			if err := npcStartFromFile(ctx, cancel, path); err != nil {
				logs.Error("%v", err)
				cancel()
			}
		}()
	}
}
