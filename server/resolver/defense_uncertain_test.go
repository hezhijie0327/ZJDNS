package resolver

import (
	"testing"
	"zjdns/edns"
)

// TestApplyDefenseUncertainty verifies the terminal-walk marking: an
// uncertain result loses Cacheable and carries the ZJDNS-private no-cache
// EDE; a certain result is untouched.
func TestApplyDefenseUncertainty(t *testing.T) {
	qr := &QueryResult{Cacheable: true}
	applyDefenseUncertainty(qr, true)
	if qr.Cacheable {
		t.Fatal("uncertain result must not be cacheable")
	}
	if !edns.IsZJDNSNoCacheEDE(qr.UpstreamEDE) {
		t.Fatalf("uncertain result must carry the no-cache EDE, got %+v", qr.UpstreamEDE)
	}
	if qr.UpstreamEDE.InfoCode != edns.EDEZJDNSDefenseUncertain {
		t.Fatalf("EDE code = %d, want %d", qr.UpstreamEDE.InfoCode, edns.EDEZJDNSDefenseUncertain)
	}

	// Certain results pass through untouched.
	untouched := &QueryResult{Cacheable: true}
	applyDefenseUncertainty(untouched, false)
	if !untouched.Cacheable || untouched.UpstreamEDE != nil {
		t.Fatal("certain result must not be marked")
	}

	// An existing no-cache EDE (fallback provenance) wins — no overwrite.
	withEDE := &QueryResult{Cacheable: true, UpstreamEDE: edns.DefenseUncertainEDE()}
	applyDefenseUncertainty(withEDE, true)
	if withEDE.UpstreamEDE.InfoCode != edns.EDEZJDNSDefenseUncertain {
		t.Fatal("existing no-cache EDE must not be overwritten")
	}
}
