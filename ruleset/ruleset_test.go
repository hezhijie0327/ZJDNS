package ruleset

import (
	"testing"
	"zjdns/config"
	"zjdns/database"
)

func testEngine(t *testing.T, rules []config.RuleSet) *Engine {
	t.Helper()
	database.Version = "3.2.12"
	db, err := database.Open(":memory:", 100, database.Options{MMapSizeMB: 1, CacheSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e := New(db, 0)
	if err := e.LoadRules(rules); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEngine_Match_Domain(t *testing.T) {
	e := testEngine(t, []config.RuleSet{
		{Tag: "google", Type: "domain", Rule: []string{"google.com", "*.youtube.com"}},
		{Tag: "other", Type: "domain", Rule: []string{"example.com"}},
	})
	tests := []struct {
		qname string
		want  string
	}{
		{"google.com.", "google"},
		{"www.google.com.", "google"},
		{"youtube.com.", "google"},
		{"www.youtube.com.", "google"},
		{"example.com.", "other"},
		{"not-example.com.", ""},
	}
	for _, tt := range tests {
		tags := e.Match(tt.qname, "1.2.3.4")
		if len(tags) > 0 {
			if !tags[tt.want] && tt.want != "" {
				t.Errorf("Match(%q) = %v, want tag %q", tt.qname, tags, tt.want)
			}
		} else if tt.want != "" {
			t.Errorf("Match(%q) = no tags, want %q", tt.qname, tt.want)
		}
	}
}

func TestEngine_Match_IP(t *testing.T) {
	e := testEngine(t, []config.RuleSet{
		{Tag: "corp", Type: "ip", Rule: []string{"10.0.0.0/8", "192.168.0.0/16"}},
		{Tag: "guest", Type: "ip", Rule: []string{"0.0.0.0/0"}},
	})
	tests := []struct {
		ip   string
		want string
	}{
		{"10.1.2.3", "corp"},
		{"192.168.1.1", "corp"},
		{"172.16.0.1", "guest"},
		{"8.8.8.8", "guest"},
	}
	for _, tt := range tests {
		tags := e.Match("example.com.", tt.ip)
		if !tags[tt.want] {
			t.Errorf("Match(%q, %q) = %v, want tag %q", "example.com.", tt.ip, tags, tt.want)
		}
	}
}

func TestEngine_Match_Both(t *testing.T) {
	e := testEngine(t, []config.RuleSet{
		{Tag: "google", Type: "domain", Rule: []string{"google.com"}},
		{Tag: "corp", Type: "ip", Rule: []string{"10.0.0.0/8"}},
	})
	tags := e.Match("google.com.", "10.1.2.3")
	if !tags["google"] || !tags["corp"] {
		t.Errorf("Match = %v, want both google and corp", tags)
	}
	tags = e.Match("google.com.", "8.8.8.8")
	if !tags["google"] || tags["corp"] {
		t.Errorf("Match = %v, want only google", tags)
	}
}

func TestEngine_HasIPTag(t *testing.T) {
	e := testEngine(t, []config.RuleSet{
		{Tag: "corp", Type: "ip", Rule: []string{"10.0.0.0/8"}},
		{Tag: "google", Type: "domain", Rule: []string{"google.com"}},
	})
	if !e.HasIPTag("corp") {
		t.Error("corp should be an IP tag")
	}
	if e.HasIPTag("google") {
		t.Error("google should NOT be an IP tag")
	}
}

func TestEngine_MatchIP_Negation(t *testing.T) {
	e := testEngine(t, []config.RuleSet{
		{Tag: "block", Type: "ip", Rule: []string{"10.0.0.0/8"}},
	})
	matched, exists := e.MatchIP("10.1.2.3", "block")
	if !matched || !exists {
		t.Errorf("should match: matched=%t exists=%t", matched, exists)
	}
	matched, exists = e.MatchIP("10.1.2.3", "!block")
	if matched || !exists {
		t.Errorf("negated should not match: matched=%t exists=%t", matched, exists)
	}
}

func TestDomainKey(t *testing.T) {
	tests := []struct{ in, want string }{
		{"google.com", "google.com"},
		{"*.google.com", "google.com"},
		{"*.youtube.com.", "youtube.com"},
	}
	for _, tt := range tests {
		if got := domainKey(tt.in); got != tt.want {
			t.Errorf("domainKey(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTLDPlusOne(t *testing.T) {
	tests := []struct{ in, want string }{
		{"www.google.com.", "google.com"},
		{"google.com.", "google.com"},
		{"com.", "com"},
		{"www.sub.example.com.", "example.com"},
	}
	for _, tt := range tests {
		if got := tldPlusOne(tt.in); got != tt.want {
			t.Errorf("tldPlusOne(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNew_InvalidPrefix(t *testing.T) {
	e := testEngine(t, []config.RuleSet{
		{Tag: "bad", Type: "ip", Rule: []string{"not-a-cidr"}},
	})
	if e.HasIPTag("bad") {
		t.Error("tag with only invalid CIDRs should have no IP matcher")
	}
}

// ── Match Cache ────────────────────────────────────────────────────────────────

func testEngineWithCache(t *testing.T, cacheEntries int, rules []config.RuleSet) *Engine {
	t.Helper()
	database.Version = "3.2.12"
	db, err := database.Open(":memory:", 100, database.Options{MMapSizeMB: 1, CacheSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e := New(db, cacheEntries)
	if err := e.LoadRules(rules); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestMatchCache_Hit(t *testing.T) {
	e := testEngineWithCache(t, 100, []config.RuleSet{
		{Tag: "google", Type: "domain", Rule: []string{"google.com"}},
	})

	if e.matchCache == nil {
		t.Fatal("matchCache should be non-nil")
	}

	// First call: SQLite → populate cache.
	tags := e.Match("www.google.com.", "1.2.3.4")
	if !tags["google"] {
		t.Fatal("first call: expected google tag")
	}

	// Second call: should hit cache (same TLD+1 key "google.com").
	tags = e.Match("mail.google.com.", "1.2.3.4")
	if !tags["google"] {
		t.Fatal("second call (cache hit): expected google tag")
	}
}

func TestMatchCache_DifferentTLD_Miss(t *testing.T) {
	e := testEngineWithCache(t, 100, []config.RuleSet{
		{Tag: "google", Type: "domain", Rule: []string{"google.com"}},
		{Tag: "other", Type: "domain", Rule: []string{"example.com"}},
	})

	// Query google.com → populates cache for "google.com" TLD+1 key.
	e.Match("www.google.com.", "1.2.3.4")

	// Query example.com → different TLD+1 key, should miss cache and hit SQLite.
	tags := e.Match("example.com.", "1.2.3.4")
	if !tags["other"] {
		t.Fatal("expected other tag for example.com")
	}
}

func TestMatchCache_LoadRulesResets(t *testing.T) {
	e := testEngineWithCache(t, 100, []config.RuleSet{
		{Tag: "google", Type: "domain", Rule: []string{"google.com"}},
	})

	// Populate cache.
	e.Match("www.google.com.", "1.2.3.4")
	if e.matchCache.Len() == 0 {
		t.Fatal("cache should be non-empty after query")
	}

	// Reload rules — cache should reset.
	err := e.LoadRules([]config.RuleSet{
		{Tag: "other", Type: "domain", Rule: []string{"example.com"}},
	})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if e.matchCache.Len() != 0 {
		t.Errorf("cache should be empty after LoadRules, got %d entries", e.matchCache.Len())
	}
}

func TestMatchCache_Disabled(t *testing.T) {
	e := testEngineWithCache(t, 0, []config.RuleSet{
		{Tag: "google", Type: "domain", Rule: []string{"google.com"}},
	})

	if e.matchCache != nil {
		t.Error("matchCache should be nil when size=0")
	}

	// Should work via SQLite.
	tags := e.Match("www.google.com.", "1.2.3.4")
	if !tags["google"] {
		t.Fatal("expected google tag with cache disabled")
	}
}

func TestMatchCache_IPRulesNotCached(t *testing.T) {
	e := testEngineWithCache(t, 100, []config.RuleSet{
		{Tag: "corp", Type: "ip", Rule: []string{"10.0.0.0/8"}},
	})

	// IP-only rules should not populate the domain cache.
	tags := e.Match("any.domain.", "10.1.2.3")
	if !tags["corp"] {
		t.Fatal("expected corp tag")
	}

	// Domain cache should still be empty (no domain rules to cache).
	if e.matchCache.Len() != 0 {
		t.Errorf("domain cache should be empty for IP-only rules, got %d entries", e.matchCache.Len())
	}
}
