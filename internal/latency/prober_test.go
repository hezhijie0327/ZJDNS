package latency

import (
	"context"
	"net"
	"testing"

	"zjdns/config"
)

func TestNew_NilContext(t *testing.T) {
	p := New([]config.LatencyProbeStep{{Protocol: "tcp", Timeout: 50}}, nil)
	if p == nil {
		t.Fatal("New should return non-nil Prober even with nil context")
	}
	if p.ctx == nil {
		t.Fatal("Prober should have non-nil background context")
	}
}

func TestNew_EmptySteps(t *testing.T) {
	p := New(nil, context.Background())
	if p == nil {
		t.Fatal("New should return non-nil Prober")
	}
}

func TestProbeIPsLatency_NilProber(t *testing.T) {
	var p *Prober
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}
	result, _ := p.ProbeIPsLatency(context.Background(), ips)
	if len(result) != len(ips) {
		t.Fatalf("nil Prober should return input as-is, got %d", len(result))
	}
}

func TestProbeIPsLatency_Empty(t *testing.T) {
	p := New([]config.LatencyProbeStep{{Protocol: "tcp", Timeout: 50}}, context.Background())
	result, _ := p.ProbeIPsLatency(context.Background(), nil)
	if result != nil {
		t.Error("ProbeIPsLatency with nil input should return nil")
	}
}

func TestProbeIPsLatency_Single(t *testing.T) {
	p := New([]config.LatencyProbeStep{{Protocol: "tcp", Timeout: 50}}, context.Background())
	ips := []net.IP{net.ParseIP("1.1.1.1")}
	result, _ := p.ProbeIPsLatency(context.Background(), ips)
	if len(result) != 1 {
		t.Fatalf("single IP should be returned, got %d", len(result))
	}
	if !result[0].Equal(ips[0]) {
		t.Error("single IP should be unchanged")
	}
}

func TestProbeIPsLatency_NoSteps(t *testing.T) {
	p := New(nil, context.Background())
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}
	result, _ := p.ProbeIPsLatency(context.Background(), ips)
	if len(result) != 2 {
		t.Fatalf("no steps should return input as-is, got %d", len(result))
	}
}

func TestProbeIPsLatency_LoopbackPrivate(t *testing.T) {
	p := New([]config.LatencyProbeStep{{Protocol: "tcp", Timeout: 50}}, context.Background())
	ips := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("192.168.1.1"),
		net.ParseIP("10.0.0.1"),
		net.ParseIP("::1"),
	}
	result, _ := p.ProbeIPsLatency(context.Background(), ips)
	if len(result) != 4 {
		t.Fatalf("loopback/private IPs should be returned as-is, got %d", len(result))
	}
	// Loopback and private IPs should get MaxInt64 latency and sort to end.
	// Since all are unprobeable, order should be unchanged.
}

func TestNormalizeProbeProtocol(t *testing.T) {
	tests := []struct{ in, want string }{
		{"ping", "ping"},
		{"icmp", "ping"},
		{"ICMP", "ping"},
		{"tcp", "tcp"},
		{"udp", "udp"},
		{"http", "http"},
	}
	for _, tt := range tests {
		got := normalizeProbeProtocol(tt.in)
		if got != tt.want {
			t.Errorf("normalizeProbeProtocol(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
