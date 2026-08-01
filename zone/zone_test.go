package zone

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"zjdns/config"
	"zjdns/internal/ttl"

	"codeberg.org/miekg/dns"
)

func TestEvaluator_LoadRules(t *testing.T) {
	z := New()
	if z.HasRules() {
		t.Error("new Evaluator should have no rules")
	}

	err := z.LoadRules([]config.ZoneRule{
		{Name: "example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if !z.HasRules() {
		t.Error("HasRules should return true after loading")
	}
}

func TestEvaluator_Evaluate_Answer(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "static.example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	result := z.Evaluate("static.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("expected match")
	}
	if result.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want NOERROR", result.Rcode)
	}
	if len(result.Answer) != 1 {
		t.Fatalf("Answer len = %d, want 1", len(result.Answer))
	}
	a, ok := result.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", result.Answer[0])
	}
	if a.A.String() != "10.0.0.1" {
		t.Errorf("A = %s, want 10.0.0.1", a.A.String())
	}
}

func TestEvaluator_Evaluate_NoMatch(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// Different qtype.
	result := z.Evaluate("example.com.", dns.TypeAAAA, dns.ClassINET, nil)
	if result.Matched {
		t.Error("AAAA query should not match A-only rule")
	}

	// Different domain.
	result = z.Evaluate("other.com.", dns.TypeA, dns.ClassINET, nil)
	if result.Matched {
		t.Error("other.com should not match")
	}
}

func TestEvaluator_Evaluate_NXDOMAIN(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "blocked.com", Rcode: dns.RcodeNameError},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// Sentinel rule matches all qtypes.
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT} {
		result := z.Evaluate("blocked.com.", qt, dns.ClassINET, nil)
		if !result.Matched {
			t.Errorf("qtype=%d should match sentinel rule", qt)
		}
		if result.Rcode != dns.RcodeNameError {
			t.Errorf("qtype=%d Rcode = %d, want NXDOMAIN", qt, result.Rcode)
		}
		if len(result.Answer) != 0 {
			t.Errorf("qtype=%d Answer len = %d, want 0", qt, len(result.Answer))
		}
	}
}

func TestEvaluator_Evaluate_AuthorityAndAdditional(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{
			Name: "test.example.com",
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300},
			},
			Authority: []config.ZoneRecord{
				{Type: dns.TypeNS, Content: "ns1.example.com.", TTL: 3600},
			},
			Additional: []config.ZoneRecord{
				{Type: dns.TypeA, Name: "ns1.example.com", Content: "10.0.0.2", TTL: 3600},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	result := z.Evaluate("test.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("expected match")
	}
	if len(result.Answer) != 1 {
		t.Errorf("Answer len = %d, want 1", len(result.Answer))
	}
	if len(result.Authority) != 1 {
		t.Errorf("Authority len = %d, want 1", len(result.Authority))
	}
	if len(result.Additional) != 1 {
		t.Errorf("Additional len = %d, want 1", len(result.Additional))
	}
}

func TestEvaluator_Evaluate_MultipleTypes(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{
			Name: "multi.example.com",
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300},
				{Type: dns.TypeAAAA, Content: "::1", TTL: 300},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// A query returns only A.
	aResult := z.Evaluate("multi.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !aResult.Matched {
		t.Fatal("A query: expected match")
	}
	if len(aResult.Answer) != 1 {
		t.Errorf("A query: Answer len = %d, want 1", len(aResult.Answer))
	}
	if _, ok := aResult.Answer[0].(*dns.A); !ok {
		t.Errorf("A query: expected A record, got %T", aResult.Answer[0])
	}

	// AAAA query returns only AAAA.
	aaaaResult := z.Evaluate("multi.example.com.", dns.TypeAAAA, dns.ClassINET, nil)
	if !aaaaResult.Matched {
		t.Fatal("AAAA query: expected match")
	}
	if len(aaaaResult.Answer) != 1 {
		t.Errorf("AAAA query: Answer len = %d, want 1", len(aaaaResult.Answer))
	}
	if _, ok := aaaaResult.Answer[0].(*dns.AAAA); !ok {
		t.Errorf("AAAA query: expected AAAA record, got %T", aaaaResult.Answer[0])
	}
}

func TestEvaluator_Wildcard(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "*.wild.example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// Wildcard matches subdomains.
	result := z.Evaluate("sub.wild.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("wildcard should match subdomain")
	}

	// Wildcard matches deep subdomains.
	result = z.Evaluate("deep.sub.wild.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("wildcard should match deep subdomain")
	}

	// Wildcard does NOT match the base domain.
	result = z.Evaluate("wild.example.com.", dns.TypeA, dns.ClassINET, nil)
	if result.Matched {
		t.Error("wildcard should not match base domain")
	}
}

func TestEvaluator_Wildcard_TypeFilter(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "*.wild.example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// AAAA query should not match A-only wildcard.
	result := z.Evaluate("sub.wild.example.com.", dns.TypeAAAA, dns.ClassINET, nil)
	if result.Matched {
		t.Error("AAAA query should not match A-only wildcard")
	}
}

func TestEvaluator_ExactWinsOverWildcard(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "*.example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "1.1.1.1", TTL: 300}}},
		{Name: "specific.example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "2.2.2.2", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	result := z.Evaluate("specific.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("expected match")
	}
	a := result.Answer[0].(*dns.A)
	if a.A.String() != "2.2.2.2" {
		t.Errorf("exact should win: got %s, want 2.2.2.2", a.A.String())
	}
}

func TestEvaluator_NoRules(t *testing.T) {
	z := New()
	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	if result.Matched {
		t.Error("empty evaluator should not match")
	}
}

func TestEvaluator_CreatedAt(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	if result.CreatedAt == 0 {
		t.Error("CreatedAt should be non-zero")
	}
}

func TestEvaluator_RcodeOnlyWithRecords(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{
			Name:  "mixed.example.com",
			Rcode: dns.RcodeRefused,
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// A query returns REFUSED with records.
	aResult := z.Evaluate("mixed.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !aResult.Matched {
		t.Fatal("A query: expected match")
	}
	if aResult.Rcode != dns.RcodeRefused {
		t.Errorf("A query: Rcode = %d, want REFUSED", aResult.Rcode)
	}
	if len(aResult.Answer) != 1 {
		t.Errorf("A query: Answer len = %d, want 1", len(aResult.Answer))
	}

	// AAAA query has no matching type, so... wait. The rule has answer records
	// so it creates non-sentinel keys. AAAA won't match.
	aaaaResult := z.Evaluate("mixed.example.com.", dns.TypeAAAA, dns.ClassINET, nil)
	if aaaaResult.Matched {
		t.Error("AAAA query should not match (no AAAA records in rule)")
	}
}

func TestEvaluator_FileImport_Basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zone.txt")
	content := "# Zone file example\n" +
		".blocked.com rcode=3\n" +
		".custom.example.com\n" +
		"  1  10.0.0.1  300\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	z := New()
	err := z.LoadRules([]config.ZoneRule{{File: path}})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// blocked.com returns NXDOMAIN for all types.
	result := z.Evaluate("blocked.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("blocked.com A: expected match")
	}
	if result.Rcode != dns.RcodeNameError {
		t.Errorf("blocked.com A: Rcode = %d, want NXDOMAIN", result.Rcode)
	}

	// custom.example.com A returns a record.
	result = z.Evaluate("custom.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("custom.example.com A: expected match")
	}
	if len(result.Answer) != 1 {
		t.Errorf("custom.example.com A: Answer len = %d, want 1", len(result.Answer))
	}
}

func TestEvaluator_FileImport_Wildcard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zone.txt")
	content := "*.wild.com\n" +
		"  1  10.0.0.1  300\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	z := New()
	err := z.LoadRules([]config.ZoneRule{{File: path}})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	result := z.Evaluate("sub.wild.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("wildcard should match subdomain")
	}
}

func TestEvaluator_FileImport_Comments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zone.txt")
	content := "# This is a comment\n" +
		"# Another comment\n" +
		".example.com\n" +
		"  1  10.0.0.1  300\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	z := New()
	err := z.LoadRules([]config.ZoneRule{{File: path}})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("expected match")
	}
}

func TestEvaluator_FileImport_AuthorityAndAdditional(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zone.txt")
	content := ".example.com\n" +
		"  1  10.0.0.1  300\n" +
		"  6  \"ns1.example.com. admin.example.com. 1 3600 900 86400 3600\"  3600  section=authority\n" +
		"  1  10.0.0.2  3600  name=ns1.example.com  section=additional\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	z := New()
	err := z.LoadRules([]config.ZoneRule{{File: path}})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("expected match")
	}
	if len(result.Answer) != 1 {
		t.Errorf("Answer len = %d, want 1", len(result.Answer))
	}
	if len(result.Authority) != 1 {
		t.Errorf("Authority len = %d, want 1", len(result.Authority))
	}
	if len(result.Additional) != 1 {
		t.Errorf("Additional len = %d, want 1", len(result.Additional))
	}
}

// ---------------------------------------------------------------------------
// Match tag tests
// ---------------------------------------------------------------------------

func TestEvaluator_MatchTags_PositiveMatch(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "vpn.example.com", Match: []string{"corp"}, Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
		{Name: "vpn.example.com", Match: []string{"guest"}, Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.2", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// Client with "corp" tag should match the corp rule.
	result := z.Evaluate("vpn.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"corp": true})
	if !result.Matched {
		t.Fatal("corp-tagged client: expected match")
	}
	a := result.Answer[0].(*dns.A)
	if a.A.String() != "10.0.0.1" {
		t.Errorf("corp-tagged client: A = %s, want 10.0.0.1", a.A.String())
	}

	// Client with "guest" tag should match the guest rule.
	result = z.Evaluate("vpn.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"guest": true})
	if !result.Matched {
		t.Fatal("guest-tagged client: expected match")
	}
	a = result.Answer[0].(*dns.A)
	if a.A.String() != "10.0.0.2" {
		t.Errorf("guest-tagged client: A = %s, want 10.0.0.2", a.A.String())
	}

	// Client with neither tag should not match.
	result = z.Evaluate("vpn.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{})
	if result.Matched {
		t.Error("untagged client: should not match any rule")
	}
}

func TestEvaluator_MatchTags_Negate(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{
			Name:  "vpn.example.com",
			Match: []string{"!corp", "!guest"},
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "127.0.0.1", TTL: 300},
				{Type: dns.TypeAAAA, Content: "::1", TTL: 300},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// Client with neither tag should match (both negations satisfied).
	result := z.Evaluate("vpn.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{})
	if !result.Matched {
		t.Fatal("untagged client: expected match (neither corp nor guest)")
	}
	if len(result.Answer) != 1 {
		t.Fatalf("Answer len = %d, want 1", len(result.Answer))
	}
	a := result.Answer[0].(*dns.A)
	if a.A.String() != "127.0.0.1" {
		t.Errorf("A = %s, want 127.0.0.1", a.A.String())
	}

	// Client with only "corp" should NOT match (!corp fails).
	result = z.Evaluate("vpn.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"corp": true})
	if result.Matched {
		t.Error("corp-tagged client: should NOT match (!corp negates)")
	}

	// Client with only "guest" should NOT match (!guest fails).
	result = z.Evaluate("vpn.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"guest": true})
	if result.Matched {
		t.Error("guest-tagged client: should NOT match (!guest negates)")
	}

	// Client with BOTH tags should NOT match.
	result = z.Evaluate("vpn.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"corp": true, "guest": true})
	if result.Matched {
		t.Error("corp+guest-tagged client: should NOT match (both negations fail)")
	}
}

// TestEvaluator_MatchTags_MixedSameQType reproduces the bug where two rows
// share the same (qname, qtype, qclass) but have different match_tags —
// one with a negative tag, one with a positive tag. A
// approach only checked one row arbitrarily.
func TestEvaluator_MatchTags_MixedSameQType(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{
			Name:  "vpn.example.com",
			Match: []string{"!net_local"}, // negative: matches clients NOT in net_local
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "127.0.0.1", TTL: 300},
				{Type: dns.TypeAAAA, Content: "::1", TTL: 300},
			},
		},
		{
			Name:  "vpn.example.com",
			Rcode: dns.RcodeNameError,
			Match: []string{"net_local"}, // positive: matches clients IN net_local
			Answer: []config.ZoneRecord{
				{Type: dns.TypeAAAA}, // empty AAAA record
			},
		},
		{
			Name:  "vpn.example.com",
			Match: []string{"net_local"}, // positive: matches clients IN net_local
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "10.192.7.1", TTL: 300},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// External client (no tags) — should match the !net_local rule → 127.0.0.1.
	result := z.Evaluate("vpn.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{})
	if !result.Matched {
		t.Fatal("untagged client A query: expected match")
	}
	if result.Rcode != dns.RcodeSuccess {
		t.Errorf("untagged client A: Rcode = %d, want NOERROR", result.Rcode)
	}
	if len(result.Answer) != 1 {
		t.Fatalf("untagged client A: Answer len = %d, want 1", len(result.Answer))
	}
	a := result.Answer[0].(*dns.A)
	if a.A.String() != "127.0.0.1" {
		t.Errorf("untagged client A: A = %s, want 127.0.0.1", a.A.String())
	}

	// External client — AAAA query → ::1 from !net_local rule.
	result = z.Evaluate("vpn.example.com.", dns.TypeAAAA, dns.ClassINET, map[string]bool{})
	if !result.Matched {
		t.Fatal("untagged client AAAA query: expected match")
	}
	if len(result.Answer) != 1 {
		t.Fatalf("untagged client AAAA: Answer len = %d, want 1", len(result.Answer))
	}
	aaaa := result.Answer[0].(*dns.AAAA)
	if aaaa.AAAA.String() != "::1" {
		t.Errorf("untagged client AAAA: AAAA = %s, want ::1", aaaa.AAAA.String())
	}

	// Local client (net_local tag) — A query → should match net_local rule → 10.192.7.1.
	result = z.Evaluate("vpn.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"net_local": true})
	if !result.Matched {
		t.Fatal("local client A query: expected match (this was the bug)")
	}
	if result.Rcode != dns.RcodeSuccess {
		t.Errorf("local client A: Rcode = %d, want NOERROR", result.Rcode)
	}
	if len(result.Answer) != 1 {
		t.Fatalf("local client A: Answer len = %d, want 1", len(result.Answer))
	}
	a = result.Answer[0].(*dns.A)
	if a.A.String() != "10.192.7.1" {
		t.Errorf("local client A: A = %s, want 10.192.7.1", a.A.String())
	}

	// Local client (net_local tag) — AAAA query → should match net_local rcode=3 rule.
	result = z.Evaluate("vpn.example.com.", dns.TypeAAAA, dns.ClassINET, map[string]bool{"net_local": true})
	if !result.Matched {
		t.Fatal("local client AAAA query: expected match")
	}
	if result.Rcode != dns.RcodeNameError {
		t.Errorf("local client AAAA: Rcode = %d, want NXDOMAIN", result.Rcode)
	}
}

// TestEvaluator_MatchTags_MultiAnd verifies AND logic: all tags must be satisfied.
func TestEvaluator_MatchTags_MultiAnd(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{
			Name:  "internal.example.com",
			Match: []string{"corp", "!guest"}, // must be corp AND NOT guest
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// Has "corp" but not "guest" → should match.
	result := z.Evaluate("internal.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"corp": true})
	if !result.Matched {
		t.Error("corp only: expected match")
	}

	// Has "corp" AND "guest" → should NOT match (!guest fails).
	result = z.Evaluate("internal.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"corp": true, "guest": true})
	if result.Matched {
		t.Error("corp+guest: should NOT match (!guest negates)")
	}

	// Has "guest" but not "corp" → should NOT match (positive "corp" requirement fails).
	result = z.Evaluate("internal.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"guest": true})
	if result.Matched {
		t.Error("guest only: should NOT match (corp required)")
	}

	// Has neither → should NOT match.
	result = z.Evaluate("internal.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{})
	if result.Matched {
		t.Error("neither: should NOT match")
	}
}

// TestEvaluator_MatchTags_Wildcard verifies that match_tags work on wildcard rules.
func TestEvaluator_MatchTags_Wildcard(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{
			Name:  "*.corp.example.com",
			Match: []string{"corp"},
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300},
			},
		},
		{
			Name:  "*.corp.example.com",
			Match: []string{"!corp"},
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "127.0.0.1", TTL: 300},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// Corp client matches the "corp" wildcard rule.
	result := z.Evaluate("sub.corp.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"corp": true})
	if !result.Matched {
		t.Fatal("corp-tagged client: expected wildcard match")
	}
	a := result.Answer[0].(*dns.A)
	if a.A.String() != "10.0.0.1" {
		t.Errorf("corp client: A = %s, want 10.0.0.1", a.A.String())
	}

	// Non-corp client matches the "!corp" wildcard rule.
	result = z.Evaluate("sub.corp.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{})
	if !result.Matched {
		t.Fatal("untagged client: expected wildcard match")
	}
	a = result.Answer[0].(*dns.A)
	if a.A.String() != "127.0.0.1" {
		t.Errorf("untagged client: A = %s, want 127.0.0.1", a.A.String())
	}
}

// TestEvaluator_MatchTags_NoTagsMatchesAll verifies that a rule without match_tags
// matches all clients regardless of their tags.
func TestEvaluator_MatchTags_NoTagsMatchesAll(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "public.example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "1.1.1.1", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// Should match with no tags.
	result := z.Evaluate("public.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Error("nil tags: expected match")
	}

	// Should match with some tags.
	result = z.Evaluate("public.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"corp": true})
	if !result.Matched {
		t.Error("corp-tagged client: expected match (no match_tags on rule)")
	}
}

func TestEvaluator_TTLCyclical(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("expected match")
	}
	if result.CreatedAt <= 0 {
		t.Error("CreatedAt should be positive")
	}

	elapsed := ttl.Elapsed(result.CreatedAt)
	deducted := ttl.DeductElapsedCyclical(result.Answer, elapsed)
	if len(deducted) != 1 {
		t.Fatalf("deducted len = %d, want 1", len(deducted))
	}
	// TTL should be <= original 300 after deduction.
	rr := deducted[0]
	if rr.Header().TTL > 300 {
		t.Errorf("deducted TTL = %d, want <= 300", rr.Header().TTL)
	}
}

// TestEvaluator_MatchScore_Priority verifies that when multiple rules match the
// same (qname, qtype), the rule with the highest matchScore wins — positive tag
// matches (score 2) beat negated fallback tags (score 1).
//
// Rules:
//  1. .svc.example.com match=!tag_a,!tag_b → 127.0.0.1 (fallback for external)
//  2. .svc.example.com match=tag_a → 10.192.7.1   (subnet A)
//  3. .svc.example.com match=tag_a rcode=3 → ""   (AAAA blocked, subnet A)
//  4. .svc.example.com match=tag_b → 10.192.39.1  (subnet B)
//  5. .svc.example.com match=tag_b rcode=3 → ""   (AAAA blocked, subnet B)
func TestEvaluator_MatchScore_Priority(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{
			Name:  "svc.example.com",
			Match: []string{"!tag_a", "!tag_b"},
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "127.0.0.1", TTL: 300},
			},
		},
		{
			Name:  "svc.example.com",
			Match: []string{"tag_a"},
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "10.192.7.1", TTL: 300},
			},
		},
		{
			Name:  "svc.example.com",
			Rcode: dns.RcodeNameError,
			Match: []string{"tag_a"},
			Answer: []config.ZoneRecord{
				{Type: dns.TypeAAAA},
			},
		},
		{
			Name:  "svc.example.com",
			Match: []string{"tag_b"},
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "10.192.39.1", TTL: 300},
			},
		},
		{
			Name:  "svc.example.com",
			Rcode: dns.RcodeNameError,
			Match: []string{"tag_b"},
			Answer: []config.ZoneRecord{
				{Type: dns.TypeAAAA},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// ── Subnet A (tag_a) — A query → 10.192.7.1 ──────────────────────────
	result := z.Evaluate("svc.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"tag_a": true})
	if !result.Matched {
		t.Fatal("tag_a A: expected match")
	}
	if result.Rcode != dns.RcodeSuccess {
		t.Errorf("tag_a A: rcode = %d, want NOERROR", result.Rcode)
	}
	if len(result.Answer) != 1 {
		t.Fatalf("tag_a A: answer len = %d, want 1", len(result.Answer))
	}
	a := result.Answer[0].(*dns.A)
	if a.A.String() != "10.192.7.1" {
		t.Errorf("tag_a A: A = %s, want 10.192.7.1", a.A.String())
	}

	// ── Subnet A (tag_a) — AAAA query → NXDOMAIN ─────────────────────────
	result = z.Evaluate("svc.example.com.", dns.TypeAAAA, dns.ClassINET, map[string]bool{"tag_a": true})
	if !result.Matched {
		t.Fatal("tag_a AAAA: expected match")
	}
	if result.Rcode != dns.RcodeNameError {
		t.Errorf("tag_a AAAA: rcode = %d, want NXDOMAIN", result.Rcode)
	}

	// ── Subnet B (tag_b) — A query → 10.192.39.1 ──────────────────────────
	result = z.Evaluate("svc.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"tag_b": true})
	if !result.Matched {
		t.Fatal("tag_b A: expected match")
	}
	if result.Rcode != dns.RcodeSuccess {
		t.Errorf("tag_b A: rcode = %d, want NOERROR", result.Rcode)
	}
	if len(result.Answer) != 1 {
		t.Fatalf("tag_b A: answer len = %d, want 1", len(result.Answer))
	}
	a = result.Answer[0].(*dns.A)
	if a.A.String() != "10.192.39.1" {
		t.Errorf("tag_b A: A = %s, want 10.192.39.1", a.A.String())
	}

	// ── Subnet B (tag_b) — AAAA query → NXDOMAIN ─────────────────────────
	result = z.Evaluate("svc.example.com.", dns.TypeAAAA, dns.ClassINET, map[string]bool{"tag_b": true})
	if !result.Matched {
		t.Fatal("tag_b AAAA: expected match")
	}
	if result.Rcode != dns.RcodeNameError {
		t.Errorf("tag_b AAAA: rcode = %d, want NXDOMAIN", result.Rcode)
	}

	// ── No tags (external) — A query → 127.0.0.1 (fallback) ──────────────
	result = z.Evaluate("svc.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{})
	if !result.Matched {
		t.Fatal("untagged A: expected match")
	}
	if result.Rcode != dns.RcodeSuccess {
		t.Errorf("untagged A: rcode = %d, want NOERROR", result.Rcode)
	}
	if len(result.Answer) != 1 {
		t.Fatalf("untagged A: answer len = %d, want 1", len(result.Answer))
	}
	a = result.Answer[0].(*dns.A)
	if a.A.String() != "127.0.0.1" {
		t.Errorf("untagged A: A = %s, want 127.0.0.1", a.A.String())
	}

	// ── No tags (external) — AAAA query → no specific AAAA fallback, unmatched
	result = z.Evaluate("svc.example.com.", dns.TypeAAAA, dns.ClassINET, map[string]bool{})
	if result.Matched {
		t.Error("untagged AAAA: should not match (no AAAA fallback rule)")
	}

	// ── nil matchedTags (no tag matcher) — should behave like empty map ─────
	result = z.Evaluate("svc.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("nil-matchedTags A: expected match (fallback)")
	}
	if len(result.Answer) != 1 {
		t.Fatalf("nil-matchedTags A: answer len = %d, want 1", len(result.Answer))
	}
	a = result.Answer[0].(*dns.A)
	if a.A.String() != "127.0.0.1" {
		t.Errorf("nil-matchedTags A: A = %s, want 127.0.0.1 (fallback)", a.A.String())
	}
}

// TestEvaluator_MatchTags_SubnetPriority reproduces the exact scenario from
// demo.zone.txt: two subnets with fallback, verifying that a client from
// subnet B gets subnet B's IP, not the fallback.
//
// Zone rules (all for vpn.zhijie.online, type A):
//
//	rule 1: match=!net_10_192_0_0,!net_10_192_32_0 → 127.0.0.1 (fallback)
//	rule 2: match=net_10_192_0_0                   → 10.192.7.1  (subnet A)
//	rule 3: match=net_10_192_32_0                  → 10.192.39.1 (subnet B)
func TestEvaluator_MatchTags_SubnetPriority(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{
			Name:  "vpn.zhijie.online",
			Match: []string{"!net_10_192_0_0", "!net_10_192_32_0"},
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "127.0.0.1", TTL: 300},
			},
		},
		{
			Name:  "vpn.zhijie.online",
			Match: []string{"net_10_192_0_0"},
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "10.192.7.1", TTL: 300},
			},
		},
		{
			Name:  "vpn.zhijie.online",
			Match: []string{"net_10_192_32_0"},
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, Content: "10.192.39.1", TTL: 300},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// Client in subnet B (10.192.32.0/24) → should get 10.192.39.1.
	result := z.Evaluate("vpn.zhijie.online.", dns.TypeA, dns.ClassINET, map[string]bool{"net_10_192_32_0": true})
	if !result.Matched {
		t.Fatal("subnet B client: expected match (this is the bug)")
	}
	if result.Rcode != dns.RcodeSuccess {
		t.Errorf("subnet B client: rcode = %d, want NOERROR", result.Rcode)
	}
	if len(result.Answer) != 1 {
		t.Fatalf("subnet B client: answer len = %d, want 1", len(result.Answer))
	}
	a := result.Answer[0].(*dns.A)
	if a.A.String() != "10.192.39.1" {
		t.Errorf("subnet B client: A = %s, want 10.192.39.1 (got fallback: 127.0.0.1?)", a.A.String())
	}

	// Client in subnet A (10.192.0.0/19) → should get 10.192.7.1.
	result = z.Evaluate("vpn.zhijie.online.", dns.TypeA, dns.ClassINET, map[string]bool{"net_10_192_0_0": true})
	if !result.Matched {
		t.Fatal("subnet A client: expected match")
	}
	if len(result.Answer) != 1 {
		t.Fatalf("subnet A client: answer len = %d, want 1", len(result.Answer))
	}
	a = result.Answer[0].(*dns.A)
	if a.A.String() != "10.192.7.1" {
		t.Errorf("subnet A client: A = %s, want 10.192.7.1", a.A.String())
	}

	// External client (no tags) → should get fallback 127.0.0.1.
	result = z.Evaluate("vpn.zhijie.online.", dns.TypeA, dns.ClassINET, map[string]bool{})
	if !result.Matched {
		t.Fatal("external client: expected fallback match")
	}
	if len(result.Answer) != 1 {
		t.Fatalf("external client: answer len = %d, want 1", len(result.Answer))
	}
	a = result.Answer[0].(*dns.A)
	if a.A.String() != "127.0.0.1" {
		t.Errorf("external client: A = %s, want 127.0.0.1", a.A.String())
	}

	// External client (nil matchedTags) → should get fallback 127.0.0.1.
	result = z.Evaluate("vpn.zhijie.online.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("nil-matchedTags client: expected fallback match")
	}
	if len(result.Answer) != 1 {
		t.Fatalf("nil-matchedTags client: answer len = %d, want 1", len(result.Answer))
	}
	a = result.Answer[0].(*dns.A)
	if a.A.String() != "127.0.0.1" {
		t.Errorf("nil-matchedTags client: A = %s, want 127.0.0.1", a.A.String())
	}
}

// TestEvaluator_BypassRule verifies that a rule with only Match (no Name/File)
// acts as a global bypass: matching clients skip all zone rules.
func TestEvaluator_BypassRule(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Match: []string{"gateway"}},
		{Name: "example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// gateway client → bypassed.
	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"gateway": true})
	if result.Matched {
		t.Error("gateway client: expected bypass (no match)")
	}

	// non-gateway client → matches zone rule.
	result = z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, map[string]bool{})
	if !result.Matched {
		t.Fatal("non-gateway client: expected match")
	}
	a := result.Answer[0].(*dns.A)
	if a.A.String() != "10.0.0.1" {
		t.Errorf("non-gateway client: A = %s, want 10.0.0.1", a.A.String())
	}
}

// TestEvaluator_BypassRule_Negate verifies bypass with !tag.
func TestEvaluator_BypassRule_Negate(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Match: []string{"!gateway"}},
		{Name: "example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// gateway client → not bypassed, matches zone rule.
	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"gateway": true})
	if !result.Matched {
		t.Fatal("gateway client: expected match")
	}

	// non-gateway client → bypassed.
	result = z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, map[string]bool{})
	if result.Matched {
		t.Error("non-gateway client: expected bypass (no match)")
	}
}

// TestEvaluator_BypassOnly verifies bypass rules work with no content rules.
func TestEvaluator_BypassOnly(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Match: []string{"gateway"}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"gateway": true})
	if result.Matched {
		t.Error("gateway client: expected bypass")
	}

	result = z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, map[string]bool{})
	if result.Matched {
		t.Error("non-gateway client: expected no match (no rules)")
	}
}

// TestEvaluator_BypassMulti verifies multiple bypass rules.
func TestEvaluator_BypassMulti(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Match: []string{"gateway"}},
		{Match: []string{"guest"}},
		{Name: "example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// gateway client → bypassed.
	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"gateway": true})
	if result.Matched {
		t.Error("gateway client: expected bypass")
	}

	// guest client → bypassed.
	result = z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"guest": true})
	if result.Matched {
		t.Error("guest client: expected bypass")
	}

	// normal client → matches zone rule.
	result = z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, map[string]bool{})
	if !result.Matched {
		t.Fatal("normal client: expected match")
	}
}

// TestEvaluator_BypassWithFile verifies that global bypass rules work
// alongside zone file rules.
func TestEvaluator_BypassWithFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zone.txt")
	content := ".example.com\n  1  10.0.0.1  300\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Match: []string{"gateway"}},
		{File: path},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// gateway client → bypassed, skips file entries entirely.
	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"gateway": true})
	if result.Matched {
		t.Error("gateway client: expected bypass")
	}

	// non-gateway client → matches file entry.
	result = z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, map[string]bool{})
	if !result.Matched {
		t.Fatal("non-gateway client: expected match from zone file")
	}
	a := result.Answer[0].(*dns.A)
	if a.A.String() != "10.0.0.1" {
		t.Errorf("non-gateway client: A = %s, want 10.0.0.1", a.A.String())
	}
}

// TestEvaluator_FileMatchNegate verifies that parent.Match with !tag on a
// file rule acts as file-level bypass: tagged clients skip the whole file.
func TestEvaluator_FileMatchNegate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zone.txt")
	content := ".example.com\n  1  10.0.0.1  300\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	z := New()
	err := z.LoadRules([]config.ZoneRule{{
		File:  path,
		Match: []string{"!gateway"},
	}})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// gateway client → !gateway rejects → falls through.
	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"gateway": true})
	if result.Matched {
		t.Error("gateway client: expected no match (!gateway)")
	}

	// non-gateway client → matches file entry.
	result = z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, map[string]bool{})
	if !result.Matched {
		t.Fatal("non-gateway client: expected match from zone file")
	}
	a := result.Answer[0].(*dns.A)
	if a.A.String() != "10.0.0.1" {
		t.Errorf("non-gateway client: A = %s, want 10.0.0.1", a.A.String())
	}
}

// ── In-memory architecture tests ─────────────────────────────────────────────

func TestEvaluator_NoDatabaseDependency(t *testing.T) {
	z := New()
	if z.HasRules() {
		t.Error("fresh Evaluator should have no rules")
	}
	if z.exact == nil || z.wildcards == nil || z.dynamics == nil {
		t.Error("in-memory maps should be initialized")
	}
}

func TestEvaluator_WildcardMatch(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "*.example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	result := z.Evaluate("www.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched || len(result.Answer) != 1 {
		t.Fatal("wildcard should match www.example.com")
	}

	result = z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	if result.Matched {
		t.Error("wildcard should not match the base domain")
	}
}

func TestEvaluator_RcodeOnlyRule(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "blocked.com", Rcode: dns.RcodeNameError},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	result := z.Evaluate("blocked.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched || result.Rcode != dns.RcodeNameError {
		t.Errorf("sentinel rule: matched=%v rcode=%d, want matched=true rcode=%d",
			result.Matched, result.Rcode, dns.RcodeNameError)
	}
}

func TestEvaluator_MatchTagScoring(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "example.com", Match: []string{"vip"}, Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
		{Name: "example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.2", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"vip": true})
	a := result.Answer[0].(*dns.A)
	if a.A.String() != "10.0.0.1" {
		t.Errorf("tagged rule should win, got %s", a.A.String())
	}

	result = z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	a = result.Answer[0].(*dns.A)
	if a.A.String() != "10.0.0.2" {
		t.Errorf("untagged fallback, got %s", a.A.String())
	}
}

func TestEvaluator_FileImport_BareDotResetsState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zone.txt")
	// A bare "." header must reset all parsing state — a record line after
	// it must NOT be attributed to the previous domain.
	content := ".example.com\n" +
		"  1  10.0.0.1  300\n" +
		".\n" +
		"  1  10.0.0.2  300\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	z := New()
	if err := z.LoadRules([]config.ZoneRule{{File: path}}); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("example.com A: expected match")
	}
	// The stray record after the bare "." header must not have been merged
	// into example.com's answer.
	if len(result.Answer) != 1 {
		t.Fatalf("example.com A: Answer len = %d, want 1 (stray record leaked)", len(result.Answer))
	}
}

func TestEvaluator_FileImport_DotRcodeAttr(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zone.txt")
	content := ". example.com\n" + // domain header
		"  1  10.0.0.1  300\n" +
		". rcode=3\n" // attribute-only header — parsed as attributes, not a domain
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	z := New()
	if err := z.LoadRules([]config.ZoneRule{{File: path}}); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// The ". rcode=3" line must not create a bogus "RCODE=3" domain; the
	// example.com rule must be intact.
	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched || len(result.Answer) != 1 {
		t.Fatalf("example.com A: matched=%v answer=%d, want matched with 1 record", result.Matched, len(result.Answer))
	}
}

func TestEvaluator_FileImport_EscapedQuotes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zone.txt")
	// TXT content with an escaped quote must survive tokenization.
	content := ".txt.example.com\n" +
		"  16  \"hello\\\"world\"  300\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	z := New()
	if err := z.LoadRules([]config.ZoneRule{{File: path}}); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	result := z.Evaluate("txt.example.com.", dns.TypeTXT, dns.ClassINET, nil)
	if !result.Matched || len(result.Answer) != 1 {
		t.Fatalf("TXT: matched=%v answer=%d, want matched with 1 record", result.Matched, len(result.Answer))
	}
	txt, ok := result.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("expected TXT record, got %T", result.Answer[0])
	}
	joined := strings.Join(txt.Txt, "")
	// miekg/dns keeps the backslash in TXT values (\" is not unescaped by
	// the library); the point of this test is that the quoted token is not
	// truncated at the escaped quote.
	if joined != `hello\"world` {
		t.Errorf("TXT content = %q, want %q", joined, `hello\"world`)
	}
}

func TestEvaluator_WildcardDynamicRule(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{
			Name:           "*.stats.example.com",
			DynamicContent: func() []string { return []string{"value=42"} },
			Match:          []string{"internal"},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// With the tag: the wildcard dynamic rule answers.
	result := z.Evaluate("node1.stats.example.com.", dns.TypeTXT, dns.ClassCHAOS, map[string]bool{"internal": true})
	if !result.Matched || len(result.Answer) != 1 {
		t.Fatalf("tagged query: matched=%v answer=%d, want matched with 1 record", result.Matched, len(result.Answer))
	}

	// Without the tag: the rule is filtered out and nothing matches.
	result = z.Evaluate("node1.stats.example.com.", dns.TypeTXT, dns.ClassCHAOS, nil)
	if result.Matched {
		t.Fatal("dynamic rule must not answer when match tags are unsatisfied")
	}
}

// TestEvaluator_DynamicKeySpaces verifies exact and wildcard dynamic rules
// stay in their own key spaces: an exact rule answers only its own name, a
// wildcard rule answers only subdomains (never the bare name).
func TestEvaluator_DynamicKeySpaces(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "exact.example.com", DynamicContent: func() []string { return []string{"exact"} }},
		{Name: "*.wild.example.com", DynamicContent: func() []string { return []string{"wild"} }},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// Exact rule answers its own name.
	if r := z.Evaluate("exact.example.com.", dns.TypeTXT, dns.ClassCHAOS, nil); !r.Matched {
		t.Fatal("exact dynamic rule must answer its own name")
	}
	// Exact rule must NOT answer a subdomain.
	if r := z.Evaluate("sub.exact.example.com.", dns.TypeTXT, dns.ClassCHAOS, nil); r.Matched {
		t.Fatal("exact dynamic rule must not answer subdomains")
	}
	// Wildcard rule answers subdomains.
	if r := z.Evaluate("a.wild.example.com.", dns.TypeTXT, dns.ClassCHAOS, nil); !r.Matched {
		t.Fatal("wildcard dynamic rule must answer subdomains")
	}
	// Wildcard rule must NOT answer the bare name (RFC 1034 §4.3.2).
	if r := z.Evaluate("wild.example.com.", dns.TypeTXT, dns.ClassCHAOS, nil); r.Matched {
		t.Fatal("wildcard dynamic rule must not answer the bare domain")
	}
}

// TestEvaluator_DynamicScoreVsStatic verifies a static wildcard rule with
// stronger match tags wins over a generic wildcard dynamic rule.
func TestEvaluator_DynamicScoreVsStatic(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "*.cdn.example.com", DynamicContent: func() []string { return []string{"generic"} }},
		{Name: "*.cdn.example.com", Match: []string{"premium"}, Answer: []config.ZoneRecord{{Type: dns.TypeTXT, Content: "premium"}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	r := z.Evaluate("x.cdn.example.com.", dns.TypeTXT, dns.ClassINET, map[string]bool{"premium": true})
	if !r.Matched || len(r.Answer) == 0 {
		t.Fatalf("premium query: matched=%v answer=%d", r.Matched, len(r.Answer))
	}
	if txt, ok := r.Answer[0].(*dns.TXT); !ok || strings.Join(txt.Txt, "") != "premium" {
		t.Fatalf("static premium rule must win over generic dynamic, got %v", r.Answer[0])
	}
}

// TestEvaluator_FileImport_AttrDefaults verifies an attribute-only header
// (". rcode=3") sets the file-level default inherited by subsequent domain
// headers.
func TestEvaluator_FileImport_AttrDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zone.txt")
	content := ". rcode=3\n" +
		".blocked.example.com\n" +
		".ok.example.com\n" +
		"  1  10.0.0.1  300\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	z := New()
	if err := z.LoadRules([]config.ZoneRule{{File: path}}); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	// blocked.example.com inherits the file default NXDOMAIN.
	r := z.Evaluate("blocked.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !r.Matched || r.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked: matched=%v rcode=%d, want NXDOMAIN", r.Matched, r.Rcode)
	}
	// ok.example.com overrides with an actual record.
	r = z.Evaluate("ok.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !r.Matched || len(r.Answer) != 1 {
		t.Fatalf("ok: matched=%v answer=%d, want 1 record", r.Matched, len(r.Answer))
	}
}

// TestEvaluator_ExactDynamicVsStaticScore verifies the exact dynamic path
// also participates in best-scoring: a static rule with stronger match tags
// wins over a generic exact dynamic answer.
func TestEvaluator_ExactDynamicVsStaticScore(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "example.com", Match: []string{"cn"}, DynamicContent: func() []string { return []string{"dynamic"} }},
		{Name: "example.com", Match: []string{"cn", "us"}, Answer: []config.ZoneRecord{{Type: dns.TypeTXT, Content: "static"}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	r := z.Evaluate("example.com.", dns.TypeTXT, dns.ClassINET, map[string]bool{"cn": true, "us": true})
	if !r.Matched || len(r.Answer) == 0 {
		t.Fatalf("query: matched=%v answer=%d", r.Matched, len(r.Answer))
	}
	if txt, ok := r.Answer[0].(*dns.TXT); !ok || strings.Join(txt.Txt, "") != "static" {
		t.Fatalf("static rule with stronger tags must win over dynamic, got %v", r.Answer[0])
	}
	// Without the extra tag, the dynamic rule answers.
	r = z.Evaluate("example.com.", dns.TypeTXT, dns.ClassINET, map[string]bool{"cn": true})
	if txt, ok := r.Answer[0].(*dns.TXT); !ok || strings.Join(txt.Txt, "") != "dynamic" {
		t.Fatalf("dynamic rule should answer when static tags are absent, got %v", r.Answer[0])
	}
}

// TestEvaluator_ExactAndWildcardDynamicCoexist verifies the same name can
// carry both an exact and a wildcard dynamic rule without one overwriting
// the other.
func TestEvaluator_ExactAndWildcardDynamicCoexist(t *testing.T) {
	z := New()
	err := z.LoadRules([]config.ZoneRule{
		{Name: "example.com", DynamicContent: func() []string { return []string{"exact"} }},
		{Name: "*.example.com", DynamicContent: func() []string { return []string{"wild"} }},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	// Bare name → exact rule.
	r := z.Evaluate("example.com.", dns.TypeTXT, dns.ClassCHAOS, nil)
	if !r.Matched || len(r.Answer) != 1 {
		t.Fatalf("bare name: matched=%v answer=%d", r.Matched, len(r.Answer))
	}
	if txt, ok := r.Answer[0].(*dns.TXT); !ok || strings.Join(txt.Txt, "") != "exact" {
		t.Fatalf("bare name should get the exact rule, got %v", r.Answer[0])
	}
	// Subdomain → wildcard rule.
	r = z.Evaluate("sub.example.com.", dns.TypeTXT, dns.ClassCHAOS, nil)
	if !r.Matched || len(r.Answer) != 1 {
		t.Fatalf("subdomain: matched=%v answer=%d", r.Matched, len(r.Answer))
	}
	if txt, ok := r.Answer[0].(*dns.TXT); !ok || strings.Join(txt.Txt, "") != "wild" {
		t.Fatalf("subdomain should get the wildcard rule, got %v", r.Answer[0])
	}
}
