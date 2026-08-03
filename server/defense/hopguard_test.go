package defense

import (
	"maps"
	"testing"
)

const testServer = "8.8.8.8"

func feedTTL(hg *HopGuard, serverIP string, ttl uint8, count int) {
	for range count {
		hg.Feed(serverIP, ttl)
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
	if hg.armed(testServer) {
		t.Error("armed() should be false before the sample threshold")
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

	// 32 feeds of the mode arm the guard with trusted={100}.
	feedTTL(hg, testServer, 100, 32)
	if !hg.Validate(testServer, 100) {
		t.Fatal("mode TTL=100 should pass after arming")
	}

	// A secondary TTL below mode/2 is rejected.
	feedTTL(hg, testServer, 80, 4)
	if hg.Validate(testServer, 80) {
		t.Error("TTL=80 count=4 < mode/2=16 → should be rejected")
	}

	// Feed 80 until the sample count reaches the next rebuild boundary (64):
	// after decay both TTLs sit at 24, the tie-break makes 80 the mode, and
	// 100 (>= mode/2) is also retained — so 80 is now trusted.
	feedTTL(hg, testServer, 80, 28) // samples=64 → rebuild
	if !hg.Validate(testServer, 80) {
		t.Error("TTL=80 should be trusted once it becomes the mode")
	}
	if !hg.Validate(testServer, 100) {
		t.Error("TTL=100 should still be trusted (>= mode/2)")
	}
}

func TestHopGuard_LRUSeparation(t *testing.T) {
	hg := NewHopGuard()

	// Server A: TTL=100 dominates
	feedTTL(hg, "8.8.8.8", 100, 32)
	// Server B: TTL=50 dominates
	feedTTL(hg, "1.1.1.1", 50, 32)

	if !hg.armed("8.8.8.8") {
		t.Error("8.8.8.8 should be armed after 32 samples")
	}
	if !hg.armed("1.1.1.1") {
		t.Error("1.1.1.1 should be armed after 32 samples")
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
	hg.Feed("8.8.8.8", 42) // nil guard: no-op — must not panic
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

	// Mode=100 (20 times), secondary=95 (13 times) — hardened promotion
	// requires the secondary to reach count >= mode/2 = 10.
	feedTTL(hg, testServer, 100, 20)
	feedTTL(hg, testServer, 95, 13)
	feedTTL(hg, testServer, 50, 2)
	feedTTL(hg, testServer, 60, 2)
	feedTTL(hg, testServer, 70, 1) // total 38

	trusted := hg.trustedSet(testServer)
	if len(trusted) != 2 {
		t.Errorf("expected 2 trusted TTLs (100 and 95 >= mode/2), got %d: %v", len(trusted), trusted)
	}

	// TTL=93 should pass (within 95±2)
	if !hg.Validate(testServer, 93) {
		t.Error("TTL=93 should pass (within 95±2)")
	}
	// TTL=50 should be rejected (count=2 < mode/2)
	if hg.Validate(testServer, 50) {
		t.Error("TTL=50 should be rejected (count=2 < mode/2)")
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
