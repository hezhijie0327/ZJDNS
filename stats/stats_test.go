package stats

import "testing"

func TestCollector_Stats(t *testing.T) {
	c := New()
	c.Record(&Request{Protocol: "udp", Result: "hit", Rcode: 0, ResponseTime: 5})
	c.Record(&Request{Protocol: "tcp", Result: "miss", Rcode: 3, ResponseTime: 50})
	c.Record(&Request{Protocol: "udp", Result: "stale", Rcode: 0, ResponseTime: 10})

	lines := c.Stats()
	// Zero-value metrics are omitted; only non-zero categories appear.
	if !contains(lines[0], "qps=") || !contains(lines[0], "p50=5ms p95=10ms p99=10ms") {
		t.Errorf("line 0 (qps+latency): %s", lines[0])
	}
	if !contains(lines[1], "hit=1(33.3%)") || !contains(lines[1], "miss=1(33.3%)") || !contains(lines[1], "stale=1(33.3%)") {
		t.Errorf("line 1 (results): %s", lines[1])
	}
	if !contains(lines[2], "noerr=2(66.7%)") || !contains(lines[2], "nx=1(33.3%)") {
		t.Errorf("line 2 (rcodes): %s", lines[2])
	}
	if !contains(lines[3], "udp=2(66.7%)") || !contains(lines[3], "tcp=1(33.3%)") {
		t.Errorf("line 3 (protocols): %s", lines[3])
	}
	// DNSSEC and poisoned lines omitted when all values are zero.
	for _, l := range lines {
		if contains(l, "secure") || contains(l, "poisoned") {
			t.Errorf("unexpected zero-value line: %s", l)
		}
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
