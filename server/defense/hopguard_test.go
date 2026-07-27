package defense

import "testing"

const testServer = "8.8.8.8"

func TestHopGuard_AutoLearn(t *testing.T) {
	hg := NewHopGuard()

	// First call: auto-learns baseline for this server
	if !hg.Validate(testServer, 115) {
		t.Error("first Validate() should auto-learn and return true")
	}
	if hg.Expected(testServer) != 115 {
		t.Errorf("expected baseline TTL=115, got %d", hg.Expected(testServer))
	}

	// Within range (±2)
	if !hg.Validate(testServer, 113) {
		t.Error("TTL=113 should be within range of 115±2")
	}
	if !hg.Validate(testServer, 117) {
		t.Error("TTL=117 should be within range of 115±2")
	}
}

func TestHopGuard_OutOfRange(t *testing.T) {
	hg := NewHopGuard()

	if !hg.Validate(testServer, 100) {
		t.Error("first call should auto-learn")
	}

	if hg.Validate(testServer, 97) {
		t.Error("TTL=97 should be out of range 100±2")
	}
	if hg.Validate(testServer, 103) {
		t.Error("TTL=103 should be out of range 100±2")
	}

	// At boundary
	if !hg.Validate(testServer, 98) {
		t.Error("TTL=98 should be within range 100±2")
	}
	if !hg.Validate(testServer, 102) {
		t.Error("TTL=102 should be within range 100±2")
	}
}

func TestHopGuard_LRUSeparation(t *testing.T) {
	hg := NewHopGuard()

	// Different servers have independent baselines
	if !hg.Validate("8.8.8.8", 103) {
		t.Error("auto-learn for 8.8.8.8")
	}
	if !hg.Validate("1.1.1.1", 112) {
		t.Error("auto-learn for 1.1.1.1")
	}

	if hg.Expected("8.8.8.8") != 103 {
		t.Errorf("8.8.8.8 baseline should be 103, got %d", hg.Expected("8.8.8.8"))
	}
	if hg.Expected("1.1.1.1") != 112 {
		t.Errorf("1.1.1.1 baseline should be 112, got %d", hg.Expected("1.1.1.1"))
	}

	// 8.8.8.8 rejects TTL=112 (outside 103±2)
	if hg.Validate("8.8.8.8", 112) {
		t.Error("TTL=112 should be rejected for 8.8.8.8 (baseline=103)")
	}
	// 1.1.1.1 accepts TTL=112 (within 112±2)
	if !hg.Validate("1.1.1.1", 112) {
		t.Error("TTL=112 should pass for 1.1.1.1 (baseline=112)")
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
	hg.Validate(testServer, 100) // establish baseline

	if !hg.Validate(testServer, 0) {
		t.Error("zero TTL should always pass through")
	}
}

func TestHopGuard_BoundaryClamp(t *testing.T) {
	hg := NewHopGuard()

	// TTL=1: lower bound clamps to 1
	if !hg.Validate(testServer, 1) {
		t.Error("auto-learn TTL=1 should pass")
	}
	if !hg.Validate(testServer, 3) {
		t.Error("TTL=3 should be within 1±2 (clamped to 1..3)")
	}
	if hg.Validate(testServer, 4) {
		t.Error("TTL=4 should be outside 1±2")
	}
}
