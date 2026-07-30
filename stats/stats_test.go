package stats

import "testing"

func TestCollector_Stats(t *testing.T) {
	c := New()
	c.Record(&Request{Protocol: "udp", Result: "hit", Rcode: 0, ResponseTime: 5})
	c.Record(&Request{Protocol: "tcp", Result: "miss", Rcode: 3, ResponseTime: 50})
	c.Record(&Request{Protocol: "udp", Result: "stale", Rcode: 0, ResponseTime: 10})

	lines := c.Stats()
	if len(lines) != 7 {
		t.Fatalf("expected 7 lines, got %d: %v", len(lines), lines)
	}
	if !contains(lines[0], "total=3") || !contains(lines[0], "p50=") {
		t.Errorf("line 0: %s", lines[0])
	}
	if !contains(lines[1], "hit=33.3%(1)") {
		t.Errorf("line 1: %s", lines[1])
	}
	if !contains(lines[3], "noerr=2") || !contains(lines[3], "nx=1") {
		t.Errorf("line 3 (rcode): %s", lines[3])
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
