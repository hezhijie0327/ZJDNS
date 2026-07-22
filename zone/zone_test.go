package zone

import (
	"os"
	"path/filepath"
	"testing"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/ttl"

	"codeberg.org/miekg/dns"
)

func TestEvaluator_LoadRules(t *testing.T) {
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	if z.HasRules() {
		t.Error("new Evaluator should have no rules")
	}

	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	if result.Matched {
		t.Error("empty evaluator should not match")
	}
}

func TestEvaluator_CreatedAt(t *testing.T) {
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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

	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{{File: path}})
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

	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{{File: path}})
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

	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{{File: path}})
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

	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{{File: path}})
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
// one with a negative tag, one with a positive tag. The old QueryRow
// approach only checked one row arbitrarily.
func TestEvaluator_MatchTags_MixedSameQType(t *testing.T) {
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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

// TestEvaluator_Bypass verifies that bypass tags skip zone evaluation entirely.
func TestEvaluator_Bypass(t *testing.T) {
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	z.SetBypassTags([]string{"gateway"})
	err = z.LoadRules([]config.ZoneRule{
		{Name: "vpn.example.com", Match: []string{"corp"}, Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// Bypass is checked externally by the handler before calling Evaluate.
	// Evaluate itself does not check bypass — it's the caller's responsibility.
	// Verify Evaluate still matches when bypass tags are present (caller's job to skip).
	result := z.Evaluate("vpn.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"gateway": true, "corp": true})
	if !result.Matched {
		t.Error("corp+gateway client: expected match (Evaluate doesn't check bypass)")
	}

	// Client without bypass tag should match normally.
	result = z.Evaluate("vpn.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"corp": true})
	if !result.Matched {
		t.Error("corp-only client: expected match")
	}

	// Bypass() method test.
	if !z.Bypass(map[string]bool{"gateway": true}) {
		t.Error("Bypass should return true for gateway tag")
	}
	if z.Bypass(map[string]bool{"corp": true}) {
		t.Error("Bypass should return false for non-bypass tag")
	}
	if z.Bypass(map[string]bool{}) {
		t.Error("Bypass should return false for empty tags")
	}
}

func TestEvaluator_TTLCyclical(t *testing.T) {
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db, 0)
	err = z.LoadRules([]config.ZoneRule{
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

// ── Exact Cache ────────────────────────────────────────────────────────────────

func testEvaluatorWithCache(t *testing.T, cacheEntries int, rules []config.ZoneRule) *Evaluator {
	t.Helper()
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	z := New(db, cacheEntries)
	if err := z.LoadRules(rules); err != nil {
		t.Fatal(err)
	}
	return z
}

func TestZoneCache_ExactHit(t *testing.T) {
	z := testEvaluatorWithCache(t, 100, []config.ZoneRule{
		{Name: "example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})

	// First call: SQLite → populate cache.
	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("first call: expected match")
	}

	// Second call: should hit the exact cache.
	result2 := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result2.Matched {
		t.Fatal("second call (cache hit): expected match")
	}
	if len(result2.Answer) != 1 {
		t.Errorf("cache hit answer len = %d, want 1", len(result2.Answer))
	}
	a := result2.Answer[0].(*dns.A)
	if a.A.String() != "10.0.0.1" {
		t.Errorf("cache hit A = %s, want 10.0.0.1", a.A.String())
	}
}

func TestZoneCache_DifferentQType_Miss(t *testing.T) {
	z := testEvaluatorWithCache(t, 100, []config.ZoneRule{
		{Name: "example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})

	// Query A → populate cache.
	z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)

	// Query AAAA → different qtype, should miss cache and miss rule.
	result := z.Evaluate("example.com.", dns.TypeAAAA, dns.ClassINET, nil)
	if result.Matched {
		t.Error("AAAA query should not match A-only rule")
	}
}

func TestZoneCache_SkippedWithTags(t *testing.T) {
	z := testEvaluatorWithCache(t, 100, []config.ZoneRule{
		{Name: "vpn.example.com", Match: []string{"corp"}, Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})

	if z.exactCache == nil {
		t.Fatal("exactCache should be non-nil")
	}

	// Query with matchedTags → should NOT use or populate cache.
	result := z.Evaluate("vpn.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"corp": true})
	if !result.Matched {
		t.Fatal("expected match")
	}

	// Cache should still be empty (tagged queries bypass).
	if z.exactCache.Len() != 0 {
		t.Errorf("cache should be empty after tagged query, got %d entries", z.exactCache.Len())
	}
}

func TestZoneCache_LoadRulesResets(t *testing.T) {
	z := testEvaluatorWithCache(t, 100, []config.ZoneRule{
		{Name: "example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})

	// Populate cache.
	z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	if z.exactCache.Len() == 0 {
		t.Fatal("cache should be non-empty after query")
	}

	// Reload rules — cache should reset.
	err := z.LoadRules([]config.ZoneRule{
		{Name: "other.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.2", TTL: 300}}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if z.exactCache.Len() != 0 {
		t.Errorf("cache should be empty after LoadRules, got %d entries", z.exactCache.Len())
	}
}

func TestZoneCache_SentinelRule(t *testing.T) {
	z := testEvaluatorWithCache(t, 100, []config.ZoneRule{
		{Name: "blocked.com", Rcode: dns.RcodeNameError},
	})

	// Sentinel rule matches all qtypes.
	result := z.Evaluate("blocked.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched || result.Rcode != dns.RcodeNameError {
		t.Fatal("expected NXDOMAIN match")
	}

	// Different qtype — still matches (sentinel), cached under its own qtype.
	result = z.Evaluate("blocked.com.", dns.TypeAAAA, dns.ClassINET, nil)
	if !result.Matched || result.Rcode != dns.RcodeNameError {
		t.Fatal("sentinel should match AAAA too")
	}
}

func TestZoneCache_Disabled(t *testing.T) {
	z := testEvaluatorWithCache(t, 0, []config.ZoneRule{
		{Name: "example.com", Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})

	if z.exactCache != nil {
		t.Error("exactCache should be nil when size=0")
	}

	// Should work via SQLite.
	result := z.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.Matched {
		t.Fatal("expected match with cache disabled")
	}
}

func TestZoneCache_CachableFlag(t *testing.T) {
	z := testEvaluatorWithCache(t, 100, []config.ZoneRule{
		{Name: "tagged.example.com", Match: []string{"corp"}, Answer: []config.ZoneRecord{{Type: dns.TypeA, Content: "10.0.0.1", TTL: 300}}},
	})

	// Query with tags → rule is not cachable (score != 0).
	result := z.Evaluate("tagged.example.com.", dns.TypeA, dns.ClassINET, map[string]bool{"corp": true})
	if !result.Matched {
		t.Fatal("expected match")
	}

	// Same query without tags → no-match (need corp tag).
	result = z.Evaluate("tagged.example.com.", dns.TypeA, dns.ClassINET, nil)
	if result.Matched {
		t.Error("should not match without required tag")
	}

	// Re-query without tags → still no match (not cached since first query was tagged).
	result = z.Evaluate("tagged.example.com.", dns.TypeA, dns.ClassINET, nil)
	if result.Matched {
		t.Error("should still not match — tagged results are never cached")
	}
}
