package latency

import (
	"context"
	"net"
	"runtime"
	"sync"
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

func TestProbeIPsLatency_ConcurrentCalls(t *testing.T) {
	// Regression: concurrent ProbeIPsLatency calls (one per probe key) on a
	// shared Prober used to panic with "WaitGroup is reused before previous
	// Wait has returned" — the shared WaitGroup's Wait overlapped another
	// call's Add. Waits are now per-call; the shared group is lifecycle-only.
	p := New([]config.LatencyProbeStep{{Protocol: "ping", Timeout: 50}}, context.Background())
	defer p.Close()
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}

	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			_, _ = p.ProbeIPsLatency(context.Background(), ips)
		})
	}
	wg.Wait()
}

func TestProbeIPsLatency_TimeoutNoLeak(t *testing.T) {
	// Every probe times out (unreachable TEST-NET IP, 10ms step timeout).
	// Goroutines and heap objects must return to baseline — verifies the
	// timeout paths release sockets, contexts, and workers.
	p := New([]config.LatencyProbeStep{{Protocol: "tcp", Port: 443, Timeout: 10}}, context.Background())
	defer p.Close()
	unreachable := []net.IP{net.ParseIP("192.0.2.1")}

	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)
	g0 := runtime.NumGoroutine()

	for range 300 {
		_, _ = p.ProbeIPsLatency(context.Background(), unreachable)
	}
	time.Sleep(200 * time.Millisecond) // workers exit
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	g1 := runtime.NumGoroutine()

	if g1 > g0+5 {
		t.Errorf("goroutine leak: %d → %d", g0, g1)
	}
	if m1.HeapObjects > m0.HeapObjects+5000 {
		t.Errorf("heap object leak: %d → %d", m0.HeapObjects, m1.HeapObjects)
	}
}
