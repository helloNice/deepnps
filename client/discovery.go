package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	gopsnet "github.com/shirou/gopsutil/v4/net"
)

const (
	DiscoveryProtocolHTTP = "http"
	DiscoveryProtocolTCP  = "tcp"
	DiscoveryProtocolUDP  = "udp"

	DiscoveryRiskLow       = "low"
	DiscoveryRiskMedium    = "medium"
	DiscoveryRiskHigh      = "high"
	DiscoveryRiskSensitive = "sensitive"

	defaultDiscoveryProbeTimeout = 750 * time.Millisecond
	defaultDiscoveryCIDRLimit    = 256
	defaultDiscoveryConcurrency  = 32
)

type DiscoveredService struct {
	Protocol   string                 `json:"protocol"`
	Address    string                 `json:"address"`
	Port       int                    `json:"port"`
	ProcessID  int32                  `json:"pid,omitempty"`
	Name       string                 `json:"name,omitempty"`
	Confidence int                    `json:"confidence"`
	Risk       string                 `json:"risk"`
	Blocked    bool                   `json:"blocked,omitempty"`
	Evidence   []string               `json:"evidence,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type ListenerEndpoint struct {
	Protocol  string
	IP        string
	Port      int
	ProcessID int32
}

type DiscoveryOptions struct {
	ProbeTimeout int
	HTTPClient   *http.Client
	Enumerator   ListenerEnumerator
	CIDRLimit    int
	Concurrency  int
}

type ListenerEnumerator interface {
	ListListeners(context.Context) ([]ListenerEndpoint, error)
}

type GopsutilListenerEnumerator struct{}

type serviceCatalogEntry struct {
	Name            string
	Risk            string
	Blocked         bool
	PreferHTTPProbe bool
	Confidence      int
}

var defaultServiceCatalog = map[int]serviceCatalogEntry{
	21:    {Name: "FTP", Risk: DiscoveryRiskSensitive, Confidence: 70},
	22:    {Name: "SSH", Risk: DiscoveryRiskSensitive, Confidence: 80},
	23:    {Name: "Telnet", Risk: DiscoveryRiskSensitive, Confidence: 85},
	25:    {Name: "SMTP", Risk: DiscoveryRiskMedium, Confidence: 65},
	53:    {Name: "DNS", Risk: DiscoveryRiskMedium, Confidence: 70},
	80:    {Name: "HTTP", Risk: DiscoveryRiskLow, PreferHTTPProbe: true, Confidence: 75},
	135:   {Name: "Windows RPC", Risk: DiscoveryRiskSensitive, Blocked: true, Confidence: 95},
	137:   {Name: "NetBIOS", Risk: DiscoveryRiskSensitive, Blocked: true, Confidence: 90},
	138:   {Name: "NetBIOS", Risk: DiscoveryRiskSensitive, Blocked: true, Confidence: 90},
	139:   {Name: "SMB/NetBIOS", Risk: DiscoveryRiskSensitive, Blocked: true, Confidence: 95},
	389:   {Name: "LDAP", Risk: DiscoveryRiskSensitive, Confidence: 80},
	443:   {Name: "HTTPS", Risk: DiscoveryRiskLow, PreferHTTPProbe: true, Confidence: 75},
	445:   {Name: "SMB", Risk: DiscoveryRiskSensitive, Blocked: true, Confidence: 95},
	1433:  {Name: "SQL Server", Risk: DiscoveryRiskSensitive, Confidence: 85},
	1521:  {Name: "Oracle", Risk: DiscoveryRiskSensitive, Confidence: 80},
	2049:  {Name: "NFS", Risk: DiscoveryRiskSensitive, Confidence: 80},
	2375:  {Name: "Docker API", Risk: DiscoveryRiskSensitive, Confidence: 90},
	3000:  {Name: "HTTP dev server", Risk: DiscoveryRiskLow, PreferHTTPProbe: true, Confidence: 75},
	3306:  {Name: "MySQL", Risk: DiscoveryRiskSensitive, Confidence: 85},
	3389:  {Name: "Remote Desktop", Risk: DiscoveryRiskSensitive, Blocked: true, Confidence: 95},
	5000:  {Name: "HTTP app", Risk: DiscoveryRiskLow, PreferHTTPProbe: true, Confidence: 70},
	5432:  {Name: "PostgreSQL", Risk: DiscoveryRiskSensitive, Confidence: 85},
	6379:  {Name: "Redis", Risk: DiscoveryRiskSensitive, Confidence: 85},
	8000:  {Name: "HTTP app", Risk: DiscoveryRiskLow, PreferHTTPProbe: true, Confidence: 75},
	8080:  {Name: "HTTP proxy/app", Risk: DiscoveryRiskLow, PreferHTTPProbe: true, Confidence: 80},
	9000:  {Name: "HTTP app", Risk: DiscoveryRiskLow, PreferHTTPProbe: true, Confidence: 65},
	9200:  {Name: "Elasticsearch", Risk: DiscoveryRiskSensitive, Confidence: 80},
	27017: {Name: "MongoDB", Risk: DiscoveryRiskSensitive, Confidence: 85},
}

func DiscoverLocalServices(ctx context.Context, options DiscoveryOptions) ([]DiscoveredService, error) {
	enumerator := options.Enumerator
	if enumerator == nil {
		enumerator = GopsutilListenerEnumerator{}
	}
	endpoints, err := enumerator.ListListeners(ctx)
	if err != nil {
		return nil, err
	}
	services := make([]DiscoveredService, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if endpoint.Port <= 0 || endpoint.Port > 65535 {
			continue
		}
		service := classifyEndpoint(endpoint)
		if shouldHTTPProbe(service, endpoint) {
			probed := ProbeHTTPService(ctx, endpoint.IP, endpoint.Port, options)
			service = mergeProbeResult(service, probed)
		} else if endpoint.Protocol == DiscoveryProtocolTCP {
			service.Evidence = append(service.Evidence, "tcp_listener")
		} else if endpoint.Protocol == DiscoveryProtocolUDP {
			probed := ProbeUDPService(ctx, endpoint.IP, endpoint.Port, options)
			service = mergeProbeResult(service, probed)
		}
		services = append(services, service)
	}
	sortDiscoveredServices(services)
	return services, nil
}

func (GopsutilListenerEnumerator) ListListeners(ctx context.Context) ([]ListenerEndpoint, error) {
	tcpConnections, tcpErr := gopsnet.ConnectionsWithContext(ctx, "tcp")
	udpConnections, udpErr := gopsnet.ConnectionsWithContext(ctx, "udp")
	if tcpErr != nil && udpErr != nil {
		return nil, tcpErr
	}
	endpoints := make([]ListenerEndpoint, 0, len(tcpConnections)+len(udpConnections))
	for _, conn := range tcpConnections {
		if !strings.EqualFold(conn.Status, "LISTEN") {
			continue
		}
		endpoints = append(endpoints, ListenerEndpoint{
			Protocol:  DiscoveryProtocolTCP,
			IP:        conn.Laddr.IP,
			Port:      int(conn.Laddr.Port),
			ProcessID: conn.Pid,
		})
	}
	for _, conn := range udpConnections {
		endpoints = append(endpoints, ListenerEndpoint{
			Protocol:  DiscoveryProtocolUDP,
			IP:        conn.Laddr.IP,
			Port:      int(conn.Laddr.Port),
			ProcessID: conn.Pid,
		})
	}
	return endpoints, nil
}

func classifyEndpoint(endpoint ListenerEndpoint) DiscoveredService {
	protocol := strings.ToLower(strings.TrimSpace(endpoint.Protocol))
	if protocol == "" {
		protocol = DiscoveryProtocolTCP
	}
	entry, ok := defaultServiceCatalog[endpoint.Port]
	service := DiscoveredService{
		Protocol:   protocol,
		Address:    normalizeDiscoveryIP(endpoint.IP),
		Port:       endpoint.Port,
		ProcessID:  endpoint.ProcessID,
		Confidence: 45,
		Risk:       DiscoveryRiskMedium,
	}
	if ok {
		service.Name = entry.Name
		service.Risk = entry.Risk
		service.Blocked = entry.Blocked
		service.Confidence = entry.Confidence
		service.Evidence = append(service.Evidence, "catalog:"+strconv.Itoa(endpoint.Port))
	}
	if service.Name == "" {
		service.Name = strings.ToUpper(protocol) + " service"
	}
	if protocol == DiscoveryProtocolUDP && service.Risk == DiscoveryRiskLow {
		service.Risk = DiscoveryRiskMedium
	}
	return service
}

func ProbeHTTPService(ctx context.Context, host string, port int, options DiscoveryOptions) DiscoveredService {
	host = normalizeDiscoveryIP(host)
	timeout := discoveryProbeTimeout(options)
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	url := "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/"
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, url, nil)
	if err != nil {
		return probeFailureService(host, port, "http_probe_invalid_request")
	}
	req.Header.Set("User-Agent", "deepnps-discovery/1")
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return probeFailureService(host, port, "http_probe_failed")
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	service := classifyEndpoint(ListenerEndpoint{Protocol: DiscoveryProtocolHTTP, IP: host, Port: port})
	service.Protocol = DiscoveryProtocolHTTP
	service.Confidence = maxInt(service.Confidence, 95)
	if _, ok := defaultServiceCatalog[port]; !ok {
		service.Risk = DiscoveryRiskLow
	} else {
		service.Risk = riskOrDefault(service.Risk, DiscoveryRiskLow)
	}
	service.Evidence = append(service.Evidence, "http_status:"+strconv.Itoa(resp.StatusCode))
	if server := strings.TrimSpace(resp.Header.Get("Server")); server != "" {
		service.Metadata = map[string]interface{}{"server": server}
	}
	return service
}

func ProbeTCPService(ctx context.Context, host string, port int, options DiscoveryOptions) DiscoveredService {
	host = normalizeDiscoveryIP(host)
	timeout := discoveryProbeTimeout(options)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	service := classifyEndpoint(ListenerEndpoint{Protocol: DiscoveryProtocolTCP, IP: host, Port: port})
	if err != nil {
		service.Confidence = 0
		service.Evidence = append(service.Evidence, "tcp_probe_failed")
		return service
	}
	_ = conn.Close()
	service.Confidence = maxInt(service.Confidence, 70)
	service.Evidence = append(service.Evidence, "tcp_connect_ok")
	return service
}

func ProbeUDPService(ctx context.Context, host string, port int, options DiscoveryOptions) DiscoveredService {
	host = normalizeDiscoveryIP(host)
	service := classifyEndpoint(ListenerEndpoint{Protocol: DiscoveryProtocolUDP, IP: host, Port: port})
	timeout := discoveryProbeTimeout(options)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		service.Confidence = 0
		service.Evidence = append(service.Evidence, "udp_probe_failed")
		return service
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if payload := udpProbePayload(port); len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			service.Confidence = 0
			service.Evidence = append(service.Evidence, "udp_probe_failed")
			return service
		}
		buf := make([]byte, 512)
		if _, err := conn.Read(buf); err == nil {
			service.Confidence = maxInt(service.Confidence, 75)
			service.Evidence = append(service.Evidence, "udp_response")
			return service
		}
	}
	service.Confidence = maxInt(service.Confidence, 55)
	service.Evidence = append(service.Evidence, "udp_probe_sent")
	return service
}

func ScanTargets(ctx context.Context, targets []string, ports []int, options DiscoveryOptions) ([]DiscoveredService, error) {
	normalizedTargets, err := expandDiscoveryTargets(targets, discoveryCIDRLimit(options))
	if err != nil {
		return nil, err
	}
	ports = normalizeDiscoveryPorts(ports)
	if len(ports) == 0 {
		return nil, fmt.Errorf("no scan ports specified")
	}
	concurrency := options.Concurrency
	if concurrency <= 0 {
		concurrency = defaultDiscoveryConcurrency
	}
	jobs := make(chan string)
	results := make(chan DiscoveredService, len(normalizedTargets)*len(ports))
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				host, portText, _ := strings.Cut(job, ":")
				port, _ := strconv.Atoi(portText)
				result := ProbeTCPService(ctx, host, port, options)
				if result.Confidence > 0 {
					results <- result
				}
			}
		}()
	}
sendLoop:
	for _, target := range normalizedTargets {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				break sendLoop
			case jobs <- target + ":" + strconv.Itoa(port):
			}
		}
	}
	close(jobs)
	wg.Wait()
	close(results)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	out := make([]DiscoveredService, 0)
	for result := range results {
		out = append(out, result)
	}
	sortDiscoveredServices(out)
	return out, nil
}

func expandDiscoveryTargets(targets []string, cidrLimit int) ([]string, error) {
	if cidrLimit <= 0 {
		cidrLimit = defaultDiscoveryCIDRLimit
	}
	out := make([]string, 0, len(targets))
	seen := make(map[string]struct{})
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if strings.Contains(target, "/") {
			ips, err := expandDiscoveryCIDR(target, cidrLimit)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if _, ok := seen[ip]; !ok {
					seen[ip] = struct{}{}
					out = append(out, ip)
				}
			}
			continue
		}
		host := strings.Trim(target, "[]")
		if net.ParseIP(host) == nil && !validDiscoveryHostname(host) {
			return nil, fmt.Errorf("invalid discovery target %q", target)
		}
		if _, ok := seen[host]; !ok {
			seen[host] = struct{}{}
			out = append(out, host)
		}
	}
	return out, nil
}

func expandDiscoveryCIDR(raw string, limit int) ([]string, error) {
	ip, network, err := net.ParseCIDR(raw)
	if err != nil {
		return nil, err
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 CIDR scanning is supported")
	}
	out := make([]string, 0)
	for current := ip.Mask(network.Mask); network.Contains(current); current = nextIPv4(current) {
		out = append(out, current.String())
		if len(out) > limit {
			return nil, fmt.Errorf("discovery CIDR exceeds limit %d", limit)
		}
	}
	return out, nil
}

func nextIPv4(ip net.IP) net.IP {
	next := append(net.IP(nil), ip...)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func normalizeDiscoveryPorts(ports []int) []int {
	seen := make(map[int]struct{})
	out := make([]int, 0, len(ports))
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}

func shouldHTTPProbe(service DiscoveredService, endpoint ListenerEndpoint) bool {
	if endpoint.Protocol != DiscoveryProtocolTCP {
		return false
	}
	entry, ok := defaultServiceCatalog[endpoint.Port]
	return ok && entry.PreferHTTPProbe && !service.Blocked
}

func mergeProbeResult(base, probe DiscoveredService) DiscoveredService {
	if probe.Confidence <= 0 {
		base.Evidence = append(base.Evidence, probe.Evidence...)
		return base
	}
	probe.ProcessID = base.ProcessID
	probe.Blocked = base.Blocked || probe.Blocked
	return probe
}

func probeFailureService(host string, port int, evidence string) DiscoveredService {
	service := classifyEndpoint(ListenerEndpoint{Protocol: DiscoveryProtocolTCP, IP: host, Port: port})
	service.Evidence = append(service.Evidence, evidence)
	return service
}

func normalizeDiscoveryIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" || ip == "::" || ip == "0.0.0.0" {
		return "127.0.0.1"
	}
	return strings.Trim(ip, "[]")
}

func discoveryProbeTimeout(options DiscoveryOptions) time.Duration {
	if options.ProbeTimeout <= 0 {
		return defaultDiscoveryProbeTimeout
	}
	return time.Duration(options.ProbeTimeout) * time.Millisecond
}

func discoveryCIDRLimit(options DiscoveryOptions) int {
	if options.CIDRLimit <= 0 {
		return defaultDiscoveryCIDRLimit
	}
	return options.CIDRLimit
}

func riskOrDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func udpProbePayload(port int) []byte {
	switch port {
	case 53:
		return []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x09, 'l', 'o', 'c',
			'a', 'l', 'h', 'o', 's', 't', 0x00, 0x00, 0x01,
			0x00, 0x01,
		}
	default:
		return nil
	}
}

func validDiscoveryHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, part := range strings.Split(host, ".") {
		if part == "" || len(part) > 63 {
			return false
		}
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		for _, r := range part {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func sortDiscoveredServices(services []DiscoveredService) {
	sort.Slice(services, func(i, j int) bool {
		if services[i].Address != services[j].Address {
			return services[i].Address < services[j].Address
		}
		if services[i].Port != services[j].Port {
			return services[i].Port < services[j].Port
		}
		return services[i].Protocol < services[j].Protocol
	})
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
