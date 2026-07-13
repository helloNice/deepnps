package client

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

type stubListenerEnumerator struct {
	endpoints []ListenerEndpoint
	err       error
}

func (s stubListenerEnumerator) ListListeners(context.Context) ([]ListenerEndpoint, error) {
	return s.endpoints, s.err
}

func TestDiscoveryClassifiesRiskAndBlockedPorts(t *testing.T) {
	service := classifyEndpoint(ListenerEndpoint{Protocol: DiscoveryProtocolTCP, IP: "0.0.0.0", Port: 445, ProcessID: 99})
	if service.Risk != DiscoveryRiskSensitive || !service.Blocked || service.Name != "SMB" {
		t.Fatalf("SMB classification = %+v", service)
	}
	if service.Address != "127.0.0.1" || service.ProcessID != 99 {
		t.Fatalf("normalized endpoint = %+v", service)
	}
}

func TestDiscoverLocalServicesUsesEnumeratorAndHTTPProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "test-http")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("Atoi(port) error = %v", err)
	}
	services, err := DiscoverLocalServices(context.Background(), DiscoveryOptions{
		Enumerator: stubListenerEnumerator{endpoints: []ListenerEndpoint{
			{Protocol: DiscoveryProtocolTCP, IP: host, Port: port},
			{Protocol: DiscoveryProtocolTCP, IP: "127.0.0.1", Port: 3389},
		}},
	})
	if err != nil {
		t.Fatalf("DiscoverLocalServices() error = %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("services len = %d, want 2: %+v", len(services), services)
	}
	var blocked, probed bool
	for _, service := range services {
		if service.Port == 3389 && service.Blocked && service.Risk == DiscoveryRiskSensitive {
			blocked = true
		}
		if service.Port == port && service.Protocol == DiscoveryProtocolTCP {
			probed = true
		}
	}
	if !blocked {
		t.Fatalf("blocked RDP service not found: %+v", services)
	}
	if !probed {
		t.Fatalf("dynamic TCP service not found: %+v", services)
	}
}

func TestProbeHTTPServiceDetectsHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "probe")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	port, _ := strconv.Atoi(portText)
	service := ProbeHTTPService(context.Background(), host, port, DiscoveryOptions{})
	if service.Protocol != DiscoveryProtocolHTTP || service.Confidence < 90 {
		t.Fatalf("HTTP probe service = %+v", service)
	}
	if service.Risk != DiscoveryRiskLow {
		t.Fatalf("HTTP probe risk = %s, want low", service.Risk)
	}
	if service.Metadata["server"] != "probe" {
		t.Fatalf("HTTP probe metadata = %+v", service.Metadata)
	}
}

func TestProbeTCPService(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	_, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)
	service := ProbeTCPService(context.Background(), "127.0.0.1", port, DiscoveryOptions{})
	if service.Confidence < 70 || !containsDiscoveryEvidence(service.Evidence, "tcp_connect_ok") {
		t.Fatalf("TCP probe service = %+v", service)
	}
}

func TestProbeUDPService(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, portText, _ := net.SplitHostPort(conn.LocalAddr().String())
	port, _ := strconv.Atoi(portText)
	service := ProbeUDPService(context.Background(), "127.0.0.1", port, DiscoveryOptions{})
	if service.Protocol != DiscoveryProtocolUDP || service.Confidence < 55 || !containsDiscoveryEvidence(service.Evidence, "udp_probe_sent") {
		t.Fatalf("UDP probe service = %+v", service)
	}
}

func TestExpandDiscoveryTargetsLimitsCIDRAndValidatesHostnames(t *testing.T) {
	targets, err := expandDiscoveryTargets([]string{"127.0.0.1/30", "example.local"}, 4)
	if err != nil {
		t.Fatalf("expandDiscoveryTargets() error = %v", err)
	}
	if len(targets) != 5 {
		t.Fatalf("targets len = %d, want 5: %v", len(targets), targets)
	}
	if _, err := expandDiscoveryTargets([]string{"127.0.0.0/24"}, 4); err == nil {
		t.Fatal("expandDiscoveryTargets(large CIDR) error = nil, want error")
	}
	if _, err := expandDiscoveryTargets([]string{"bad host name"}, 4); err == nil {
		t.Fatal("expandDiscoveryTargets(invalid host) error = nil, want error")
	}
	if _, err := expandDiscoveryTargets([]string{"-bad.example"}, 4); err == nil {
		t.Fatal("expandDiscoveryTargets(invalid label) error = nil, want error")
	}
}

func TestScanTargetsHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ScanTargets(ctx, []string{"127.0.0.1"}, []int{80}, DiscoveryOptions{}); err == nil {
		t.Fatal("ScanTargets(canceled) error = nil, want cancellation")
	}
}

func containsDiscoveryEvidence(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
