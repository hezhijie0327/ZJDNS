package defense

import (
	"maps"
	"testing"
)

const testServer = "8.8.8.8"

func feedTTL(hg *HopGuard, serverIP string, ttl uint8, count int) {
	for range count {
		hg.Validate(serverIP, ttl)
	}
}

func TestHopGuard_LearningPhase_AllPass(t *testing.T) {
	hg := NewHopGuard()

	// All calls before minSamples: learning phase, all pass.
	for i := range hopGuardMinSamples - 1 {
		if !hg.Validate(testServer, uint8(60+i%7)) {
			t.Errorf("learning phase: call %d should pass", i+1)
		}
	}
	if hg.Expected(testServer) != 0 {
		t.Error("Expected() should return 0 before armed")
	}
}

func TestHopGuard_AdaptiveThreshold(t *testing.T) {
	hg := NewHopGuard()

	// Mode TTL=100 appears 24 times; TTL=50,60,70 appear 2-3 times each.
	// Adaptive threshold: max(4, 24/4) = 6.
	// Only TTL=100 passes the threshold.
	feedTTL(hg, testServer, 100, 24)
	feedTTL(hg, testServer, 50, 3)
	feedTTL(hg, testServer, 60, 3)
	feedTTL(hg, testServer, 70, 2) // total 32 = armed

	if !hg.armed(testServer) {
		t.Fatal("should be armed after hopGuardMinSamples")
	}

	trusted := hg.trustedSet(testServer)
	if len(trusted) != 1 {
		t.Errorf("expected 1 trusted TTL (adaptive threshold=6), got %d: %v", len(trusted), trusted)
	}
	if _, ok := trusted[100]; !ok {
		t.Error("TTL=100 should be trusted (count=24 >= threshold=6)")
	}

	// Within ±2 of trusted TTL=100
	if !hg.Validate(testServer, 98) {
		t.Error("TTL=98 should pass (within 100±2)")
	}
	if !hg.Validate(testServer, 102) {
		t.Error("TTL=102 should pass (within 100±2)")
	}

	// Outside range
	if hg.Validate(testServer, 50) {
		t.Error("TTL=50 should be rejected (not trusted, count=3 < threshold=6)")
	}
	if hg.Validate(testServer, 105) {
		t.Error("TTL=105 should be rejected (outside 100±2)")
	}
}

func TestHopGuard_NewTrustedTTL_Promoted(t *testing.T) {
	hg := NewHopGuard()

	// Mode TTL=100 (24 times), threshold=6.
	feedTTL(hg, testServer, 100, 24)
	// Feed 8 other unique TTLs (1 each).
	for ttl := uint8(50); ttl < 58; ttl++ {
		hg.Validate(testServer, ttl)
	} // total 32 → armed, trusted={100}

	// TTL=80 is rejected but histogram updated.
	hg.Validate(testServer, 80) // count=1, rejected, samples=33

	// Feed TTL=80 until count reaches 6.
	feedTTL(hg, testServer, 80, 5) // count=6, rejected 5×, samples=38

	// Feed more to reach next rebuild at 64.
	feedTTL(hg, testServer, 100, 26) // samples=64 → rebuild with threshold=max(4, 50/4)=12
	// TTL=80 count=6 < 12 → still not trusted!

	if hg.Validate(testServer, 80) {
		t.Error("TTL=80 count=6 < threshold=12 → should still be rejected")
	}

	// Feed TTL=80 to reach count=12.
	feedTTL(hg, testServer, 80, 10) // count=16, rejected, samples=74

	// Feed to next rebuild at 96.
	feedTTL(hg, testServer, 100, 22) // samples=96 → rebuild, threshold=max(4, 72/4)=18
	// TTL=80 count=16 < 18 → still not trusted. Need more...

	// Feed enough to get 80 to 18.
	feedTTL(hg, testServer, 80, 10) // count=26, samples=106
	// Need rebuild at 128...
	feedTTL(hg, testServer, 100, 22) // samples=128 → rebuild, threshold=max(4, 94/4)=23
	// TTL=80 count=26 >= 23 → trusted!

	if !hg.Validate(testServer, 80) {
		t.Error("TTL=80 count=26 >= threshold=23 → should be trusted")
	}
}

func TestHopGuard_LRUSeparation(t *testing.T) {
	hg := NewHopGuard()

	// Server A: TTL=100 dominates
	feedTTL(hg, "8.8.8.8", 100, 32)
	// Server B: TTL=50 dominates
	feedTTL(hg, "1.1.1.1", 50, 32)

	if hg.Expected("8.8.8.8") != 100 {
		t.Errorf("8.8.8.8 baseline should be 100, got %d", hg.Expected("8.8.8.8"))
	}
	if hg.Expected("1.1.1.1") != 50 {
		t.Errorf("1.1.1.1 baseline should be 50, got %d", hg.Expected("1.1.1.1"))
	}

	// TTL=50 passes for 1.1.1.1 but not 8.8.8.8
	if !hg.Validate("1.1.1.1", 50) {
		t.Error("TTL=50 should pass for 1.1.1.1")
	}
	if hg.Validate("8.8.8.8", 50) {
		t.Error("TTL=50 should be rejected for 8.8.8.8")
	}
}

func TestHopGuard_NilGuard(t *testing.T) {
	var hg *HopGuard

	if !hg.Validate("8.8.8.8", 42) {
		t.Error("nil guard should always return true")
	}
	if hg.Expected("8.8.8.8") != 0 {
		t.Errorf("nil guard Expected() should be 0, got %d", hg.Expected("8.8.8.8"))
	}
}

func TestHopGuard_ZeroTTL(t *testing.T) {
	hg := NewHopGuard()
	feedTTL(hg, testServer, 100, 32) // arm

	if !hg.Validate(testServer, 0) {
		t.Error("zero TTL should always pass through")
	}
}

func TestHopGuard_BoundaryClamp(t *testing.T) {
	hg := NewHopGuard()

	// TTL=1 appears 32 times → trusted: {1}, acceptance window clamps to [1, 3]
	feedTTL(hg, testServer, 1, 32)

	if !hg.Validate(testServer, 1) {
		t.Error("TTL=1 should pass (trusted)")
	}
	if !hg.Validate(testServer, 3) {
		t.Error("TTL=3 should be within 1±2 (clamped to 1..3)")
	}
	if hg.Validate(testServer, 4) {
		t.Error("TTL=4 should be outside 1±2")
	}
}

func TestHopGuard_AdaptiveThreshold_MultipleTrusted(t *testing.T) {
	hg := NewHopGuard()

	// Mode=100 (20 times), secondary=95 (7 times) — both >= threshold max(4,20/4)=5.
	feedTTL(hg, testServer, 100, 20)
	feedTTL(hg, testServer, 95, 7)
	feedTTL(hg, testServer, 50, 2)
	feedTTL(hg, testServer, 60, 2)
	feedTTL(hg, testServer, 70, 1) // total 32

	trusted := hg.trustedSet(testServer)
	if len(trusted) != 2 {
		t.Errorf("expected 2 trusted TTLs (100 and 95 >= threshold=5), got %d: %v", len(trusted), trusted)
	}

	// TTL=93 should pass (within 95±2)
	if !hg.Validate(testServer, 93) {
		t.Error("TTL=93 should pass (within 95±2)")
	}
	// TTL=50 should be rejected (count=2 < threshold=5)
	if hg.Validate(testServer, 50) {
		t.Error("TTL=50 should be rejected (count=2 < threshold=5)")
	}
}

// armed is a test helper.
func (h *HopGuard) armed(serverIP string) bool {
	st, ok := h.states.Get(serverIP)
	if !ok {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.armed
}

// trustedSet returns a copy of the trusted TTL set for a server (test helper).
func (h *HopGuard) trustedSet(serverIP string) map[uint8]int {
	st, ok := h.states.Get(serverIP)
	if !ok {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make(map[uint8]int, len(st.trusted))
	maps.Copy(out, st.trusted)
	return out
}
