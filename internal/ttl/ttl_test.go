package ttl

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// setNow sets NowUnix to a fixed value for deterministic tests.
func setNow(t *testing.T, ts int64) {
	t.Helper()
	orig := NowUnix
	NowUnix = func() int64 { return ts }
	t.Cleanup(func() { NowUnix = orig })
}

// ── IsExpired ──────────────────────────────────────────────────────────────────

func TestIsExpired_Fresh(t *testing.T) {
	setNow(t, 1000)
	if IsExpired(900, 200) {
		t.Error("entry 100s old with TTL=200 should not be expired")
	}
}

func TestIsExpired_Expired(t *testing.T) {
	setNow(t, 1000)
	if !IsExpired(800, 100) {
		t.Error("entry 200s old with TTL=100 should be expired")
	}
}

func TestIsExpired_AtBoundary(t *testing.T) {
	setNow(t, 1000)
	// now - timestamp = 100, TTL = 100 → not expired (> not >=)
	if IsExpired(900, 100) {
		t.Error("exactly at TTL boundary should not be expired (>, not >=")
	}
}

// ── RemainingTTL ──────────────────────────────────────────────────────────────

func TestRemainingTTL_Fresh(t *testing.T) {
	setNow(t, 1000)
	// Timestamp=900, TTL=200, now=1000 → remaining=100
	got := RemainingTTL(900, 200, 30)
	if got != 100 {
		t.Errorf("fresh remaining = %d, want 100", got)
	}
}

func TestRemainingTTL_FreshNearExpiry(t *testing.T) {
	setNow(t, 1000)
	// Timestamp=900, TTL=101, now=1000 → remaining=1
	got := RemainingTTL(900, 101, 30)
	if got != 1 {
		t.Errorf("fresh remaining near expiry = %d, want 1", got)
	}
}

func TestRemainingTTL_StaleStart(t *testing.T) {
	setNow(t, 1000)
	// Timestamp=900, TTL=100, now=1000 → exactly expired, timeSinceExpiry=0
	got := RemainingTTL(900, 100, 30)
	if got != 30 {
		t.Errorf("stale at expiry = %d, want 30", got)
	}
}

func TestRemainingTTL_StaleDecrement(t *testing.T) {
	setNow(t, 1010)
	// Timestamp=900, TTL=100 → expired 10s ago
	got := RemainingTTL(900, 100, 30)
	if got != 20 {
		t.Errorf("stale after 10s = %d, want 20", got)
	}
}

func TestRemainingTTL_StaleFloor(t *testing.T) {
	setNow(t, 1029)
	// Timestamp=900, TTL=100 → expired 29s ago
	got := RemainingTTL(900, 100, 30)
	if got != 1 {
		t.Errorf("stale after 29s = %d, want 1", got)
	}
}

func TestRemainingTTL_StaleCycleReset(t *testing.T) {
	setNow(t, 1030)
	// Timestamp=900, TTL=100 → expired 30s ago → new cycle
	got := RemainingTTL(900, 100, 30)
	if got != 30 {
		t.Errorf("stale after 30s = %d, want 30 (cycle reset)", got)
	}
}

func TestRemainingTTL_StaleSecondCycle(t *testing.T) {
	setNow(t, 1040)
	// Timestamp=900, TTL=100 → expired 40s ago → 2nd cycle, 10s in
	got := RemainingTTL(900, 100, 30)
	if got != 20 {
		t.Errorf("stale after 40s = %d, want 20", got)
	}
}

func TestRemainingTTL_StaleManyCycles(t *testing.T) {
	setNow(t, 2000)
	// Timestamp=900, TTL=100 → expired 1000s ago → many cycles
	// 1000 % 30 = 10 → 30 - 10 = 20
	got := RemainingTTL(900, 100, 30)
	if got != 20 {
		t.Errorf("stale after 1000s = %d, want 20", got)
	}
}

func TestRemainingTTL_ZeroTTL(t *testing.T) {
	setNow(t, 1000)
	// Timestamp=1000, TTL=0 → immediate stale
	got := RemainingTTL(1000, 0, 30)
	if got != 30 {
		t.Errorf("zero TTL = %d, want 30 (stale immediately)", got)
	}
}

// ── CanServeExpired ───────────────────────────────────────────────────────────

func TestCanServeExpired_WithinWindow(t *testing.T) {
	setNow(t, 1000)
	// Timestamp=800, TTL=100 → expired at 900, now=1000 → 100s past expiry
	if !CanServeExpired(800, 100, 86400) {
		t.Error("entry 100s past expiry should be within 86400s window")
	}
}

func TestCanServeExpired_BeyondWindow(t *testing.T) {
	setNow(t, 100000)
	// Timestamp=800, TTL=100 → expired at 900, now=100000 → 99100s past expiry
	if CanServeExpired(800, 100, 86400) {
		t.Error("entry 99100s past expiry should be beyond 86400s window")
	}
}

func TestCanServeExpired_AtWindowBoundary(t *testing.T) {
	setNow(t, 900+86400)
	// Timestamp=800, TTL=100 → expired at 900, now=900+86400 → exactly maxAge past
	// Check: now - ts - TTL = (900+86400) - 800 - 100 = 86400 → <= maxAge → true
	if !CanServeExpired(800, 100, 86400) {
		t.Error("exactly at maxAge boundary should be servable")
	}
}

func TestCanServeExpired_NotYetExpired(t *testing.T) {
	setNow(t, 900)
	// Timestamp=800, TTL=200 → not expired yet (the caller should check IsExpired first)
	// This function only checks the window; it assumes the caller already verified IsExpired.
	// now - ts - TTL = 900 - 800 - 200 = -100
	if !CanServeExpired(800, 200, 86400) {
		t.Error("not-yet-expired entry should still pass CanServeExpired (caller guards with IsExpired)")
	}
}

// ── ShouldPrefetch ────────────────────────────────────────────────────────────

func TestShouldPrefetch_NotYet(t *testing.T) {
	setNow(t, 1000)
	// Timestamp=900, TTL=200 → 100s elapsed, 100s remaining (50%)
	if ShouldPrefetch(900, 200, 40) {
		t.Error("50% remaining should not trigger 40% prefetch")
	}
}

func TestShouldPrefetch_Triggered(t *testing.T) {
	setNow(t, 1020)
	// Timestamp=900, TTL=200 → 120s elapsed, 80s remaining (40%)
	// threshold: 200 * 40 / 100 = 80, remaining=80 <= 80 → triggers
	if !ShouldPrefetch(900, 200, 40) {
		t.Error("40% remaining should trigger prefetch")
	}
}

func TestShouldPrefetch_Expired(t *testing.T) {
	setNow(t, 1200)
	// Timestamp=900, TTL=200 → expired
	if ShouldPrefetch(900, 200, 40) {
		t.Error("expired entry should not trigger prefetch")
	}
}

func TestShouldPrefetch_ZeroThreshold(t *testing.T) {
	setNow(t, 1000)
	if ShouldPrefetch(900, 200, 0) {
		t.Error("zero threshold should never prefetch")
	}
}

func TestShouldPrefetch_Threshold100(t *testing.T) {
	setNow(t, 1000)
	// Timestamp=900, TTL=200 → 50% elapsed, threshold=100 → remaining <= 200*100/100=200
	if !ShouldPrefetch(900, 200, 100) {
		t.Error("100% threshold should always trigger prefetch when fresh")
	}
}

// ── Elapsed ───────────────────────────────────────────────────────────────────

func TestElapsed_Normal(t *testing.T) {
	setNow(t, 1050)
	got := Elapsed(1000)
	if got != 50 {
		t.Errorf("elapsed = %d, want 50", got)
	}
}

func TestElapsed_Zero(t *testing.T) {
	setNow(t, 1000)
	got := Elapsed(1000)
	if got != 0 {
		t.Errorf("elapsed at same time = %d, want 0", got)
	}
}

func TestElapsed_Future(t *testing.T) {
	setNow(t, 1000)
	got := Elapsed(1100)
	if got != 0 {
		t.Errorf("elapsed for future timestamp = %d, want 0", got)
	}
}

// ── DeductElapsedCyclical ─────────────────────────────────────────────────────

func TestDeductElapsedCyclical_Normal(t *testing.T) {
	rr := &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 120},
		A:   rdata.A{Addr: netParseIP(t, "192.0.2.1")},
	}
	result := DeductElapsedCyclical([]dns.RR{rr}, 40)
	if len(result) != 1 {
		t.Fatalf("got %d records, want 1", len(result))
	}
	if result[0].Header().TTL != 80 {
		t.Errorf("TTL = %d, want 80 (120 - 40%%120)", result[0].Header().TTL)
	}
}

func TestDeductElapsedCyclical_ResetsAtBoundary(t *testing.T) {
	rr := &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 120},
		A:   rdata.A{Addr: netParseIP(t, "192.0.2.1")},
	}
	result := DeductElapsedCyclical([]dns.RR{rr}, 120)
	if result[0].Header().TTL != 120 {
		t.Errorf("TTL = %d, want 120 (reset at boundary)", result[0].Header().TTL)
	}
}

func TestDeductElapsedCyclical_MultipleCycles(t *testing.T) {
	rr := &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 120},
		A:   rdata.A{Addr: netParseIP(t, "192.0.2.1")},
	}
	result := DeductElapsedCyclical([]dns.RR{rr}, 260)
	// 260 % 120 = 20, 120 - 20 = 100
	if result[0].Header().TTL != 100 {
		t.Errorf("TTL = %d, want 100 (120 - 260%%120)", result[0].Header().TTL)
	}
}

func TestDeductElapsedCyclical_DifferentRRs(t *testing.T) {
	rr1 := &dns.A{
		Hdr: dns.Header{Name: "a.example.com.", Class: dns.ClassINET, TTL: 60},
		A:   rdata.A{Addr: netParseIP(t, "192.0.2.1")},
	}
	rr2 := &dns.A{
		Hdr: dns.Header{Name: "b.example.com.", Class: dns.ClassINET, TTL: 120},
		A:   rdata.A{Addr: netParseIP(t, "192.0.2.2")},
	}
	result := DeductElapsedCyclical([]dns.RR{rr1, rr2}, 80)
	// rr1: 80 % 60 = 20, 60 - 20 = 40
	// rr2: 80 % 120 = 80, 120 - 80 = 40
	if result[0].Header().TTL != 40 {
		t.Errorf("rr1 TTL = %d, want 40", result[0].Header().TTL)
	}
	if result[1].Header().TTL != 40 {
		t.Errorf("rr2 TTL = %d, want 40", result[1].Header().TTL)
	}
}

func TestDeductElapsedCyclical_ZeroTTL(t *testing.T) {
	rr := &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 0},
		A:   rdata.A{Addr: netParseIP(t, "192.0.2.1")},
	}
	result := DeductElapsedCyclical([]dns.RR{rr}, 50)
	if result[0].Header().TTL != 0 {
		t.Errorf("TTL = %d, want 0 (zero TTL unchanged)", result[0].Header().TTL)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func netParseIP(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("failed to parse IP: %s", s)
	}
	return addr
}
