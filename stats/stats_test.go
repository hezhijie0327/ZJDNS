package stats

import "testing"

func TestCollector_Stats(t *testing.T) {
	c := New()
	c.Record(&Request{Protocol: "udp", Result: "hit", Rcode: 0, ResponseTime: 5})
	c.Record(&Request{Protocol: "tcp", Result: "miss", Rcode: 3, ResponseTime: 50})
	c.Record(&Request{Protocol: "udp", Result: "stale", Rcode: 0, ResponseTime: 10})

	lines := c.Stats()
	if len(lines) != 6 {
		t.Fatalf("expected 6 lines, got %d: %v", len(lines), lines)
	}
	if !contains(lines[0], "p50=5ms p95=10ms p99=10ms") {
		t.Errorf("line 0 (latency): %s", lines[0])
	}
	if !contains(lines[1], "hit=1(33.3%)") {
		t.Errorf("line 1 (results): %s", lines[1])
	}
	if !contains(lines[2], "noerr=2(66.7%)") || !contains(lines[2], "nx=1(33.3%)") {
		t.Errorf("line 2 (rcodes): %s", lines[2])
	}
	if !contains(lines[3], "udp=2(66.7%)") || !contains(lines[3], "tcp=1(33.3%)") {
		t.Errorf("line 3 (protocols): %s", lines[3])
	}
	if !contains(lines[4], "secure=0(0.0%)") || !contains(lines[4], "insecure=0(0.0%)") {
		t.Errorf("line 4 (dnssec): %s", lines[4])
	}
	if !contains(lines[5], "poisoned=0(0.0%)") {
		t.Errorf("line 5 (poisoned): %s", lines[5])
	}
}

func TestCollector_NilSafety(t *testing.T) {
	var c *Collector
	c.Record(nil)
	c.Record(&Request{Protocol: "udp", Result: "hit", Rcode: 0})
}

func TestCollector_Reset(t *testing.T) {
	c := New()
	c.Record(&Request{Protocol: "udp", Result: "hit", Rcode: 0})
	c.Reset()
	if c.total.Load() != 0 {
		t.Error("total should be 0 after reset")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
