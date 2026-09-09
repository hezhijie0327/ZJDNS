package upstream

import (
	"testing"
)

// TestHopGuardConfidentDrivesUncertaintyMark verifies the guard-state
// primitive behind the defense-uncertainty mark: Confident is false while
// the TTL baseline is learning (every response must be flagged Uncertain)
// and true once corroborated samples arm it (responses are TTL-verified,
// mark cleared).
func TestHopGuardConfidentDrivesUncertaintyMark(t *testing.T) {
	c := New()
	const addr = "127.0.0.1:1"
	hg := c.plainClient.HopGuard()
	if hg == nil {
		t.Fatal("hopguard must exist")
	}

	if hg.Confident(addr) {
		t.Fatal("unarmed baseline must not be confident — responses are defense-uncertain")
	}

	// Arm the baseline with corroborated samples (realTTL cluster).
	for range 64 {
		hg.Feed(addr, 57)
	}
	if !hg.Confident(addr) {
		t.Fatal("armed baseline must be confident — responses are TTL-verified")
	}
}
