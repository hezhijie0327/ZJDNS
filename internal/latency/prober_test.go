package latency

import (
	"context"
	"net"
	"testing"
	"time"

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

func TestProbeIPs_NilProber(t *testing.T) {
	var p *Prober
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}
	result := p.ProbeIPs(context.Background(), ips)
	if len(result) != len(ips) {
		t.Fatalf("nil Prober should return input as-is, got %d", len(result))
	}
}

func TestProbeIPs_Empty(t *testing.T) {
	p := New([]config.LatencyProbeStep{{Protocol: "tcp", Timeout: 50}}, context.Background())
	result := p.ProbeIPs(context.Background(), nil)
	if result != nil {
		t.Error("ProbeIPs with nil input should return nil")
	}
}

func TestProbeIPs_Single(t *testing.T) {
	p := New([]config.LatencyProbeStep{{Protocol: "tcp", Timeout: 50}}, context.Background())
	ips := []net.IP{net.ParseIP("1.1.1.1")}
	result := p.ProbeIPs(context.Background(), ips)
	if len(result) != 1 {
		t.Fatalf("single IP should be returned, got %d", len(result))
	}
	if !result[0].Equal(ips[0]) {
		t.Error("single IP should be unchanged")
	}
}

func TestProbeIPs_NoSteps(t *testing.T) {
	p := New(nil, context.Background())
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}
	result := p.ProbeIPs(context.Background(), ips)
	if len(result) != 2 {
		t.Fatalf("no steps should return input as-is, got %d", len(result))
	}
}

func TestProbeIPs_LoopbackPrivate(t *testing.T) {
	p := New([]config.LatencyProbeStep{{Protocol: "tcp", Timeout: 50}}, context.Background())
	ips := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("192.168.1.1"),
		net.ParseIP("10.0.0.1"),
		net.ParseIP("::1"),
	}
	result := p.ProbeIPs(context.Background(), ips)
	if len(result) != 4 {
		t.Fatalf("loopback/private IPs should be returned as-is, got %d", len(result))
	}
	// Loopback and private IPs should get MaxInt64 latency and sort to end.
	// Since all are unprobeable, order should be unchanged.
}

func TestHashIPs(t *testing.T) {
	ips1 := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}
	ips2 := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}
	ips3 := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1")}

	h1 := hashIPs(ips1)
	h2 := hashIPs(ips2)
	h3 := hashIPs(ips3)

	if h1 != h2 {
		t.Errorf("same IPs in same order should produce same hash: %x != %x", h1, h2)
	}
	if h1 == h3 {
		t.Errorf("same IPs in different order should produce different hash: %x == %x", h1, h3)
	}
}

func TestHashIPs_DifferentLength(t *testing.T) {
	h1 := hashIPs([]net.IP{net.ParseIP("1.1.1.1")})
	h2 := hashIPs([]net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")})
	if h1 == h2 {
		t.Error("different lengths should produce different hashes")
	}
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

// --- DedupCache tests ---

func TestDedupCache_GetMiss(t *testing.T) {
	dc := NewDedupCache()
	ips, ok := dc.Get(42)
	if ok || ips != nil {
		t.Error("expected miss for unknown hash")
	}
}

func TestDedupCache_SetAndGet(t *testing.T) {
	dc := NewDedupCache()
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}
	dc.Set(42, ips, 10*time.Second)

	got, ok := dc.Get(42)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got) != len(ips) || !got[0].Equal(ips[0]) || !got[1].Equal(ips[1]) {
		t.Error("cached IPs don't match")
	}
}

func TestDedupCache_Expiry(t *testing.T) {
	dc := NewDedupCache()
	ips := []net.IP{net.ParseIP("1.1.1.1")}
	dc.Set(42, ips, 1*time.Nanosecond)
	time.Sleep(10 * time.Millisecond) // ensure expiry

	_, ok := dc.Get(42)
	if ok {
		t.Error("expected miss for expired entry")
	}
}

func TestDedupCache_ZeroTTL(t *testing.T) {
	dc := NewDedupCache()
	ips := []net.IP{net.ParseIP("1.1.1.1")}
	dc.Set(42, ips, 0) // should use default TTL

	got, ok := dc.Get(42)
	if !ok || len(got) != 1 {
		t.Error("zero TTL should use default dedupTTL")
	}
}
