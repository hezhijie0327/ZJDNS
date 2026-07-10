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
	z := New(db)
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
	z := New(db)
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
	z := New(db)
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
	z := New(db)
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
	z := New(db)
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
	z := New(db)
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
	z := New(db)
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
	z := New(db)
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
	z := New(db)
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
	z := New(db)
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
	z := New(db)
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
	z := New(db)
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
	z := New(db)
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
	z := New(db)
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
	z := New(db)
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
	z := New(db)
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

func TestEvaluator_TTLCyclical(t *testing.T) {
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	z := New(db)
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
