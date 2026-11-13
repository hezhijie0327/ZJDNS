package ruleset

import (
	"net"
	"testing"
	"zjdns/config"
)

func testEngine(t *testing.T, rules []config.RuleSet) *Engine {
	t.Helper()
	e := New()
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

// TestLoadRules_DeepDomainRuleSkipped pins the Round 6 D4 fix: domain rules
// with more than two labels can never equal the TLD+1 query key, so loading
// warns and skips them instead of counting dead rules as loaded (silent
// non-matching split/block config).
func TestLoadRules_DeepDomainRuleSkipped(t *testing.T) {
	e := testEngine(t, []config.RuleSet{
		{Tag: "dead", Type: "domain", Rule: []string{"analytics.google.com", "*.deep.example.com"}},
		{Tag: "alive", Type: "domain", Rule: []string{"google.com"}},
	})
	for _, qname := range []string{
		"analytics.google.com.", "x.analytics.google.com.", "deep.example.com.", "www.deep.example.com.",
	} {
		if tags := e.Match(qname, "1.2.3.4"); tags["dead"] {
			t.Errorf("Match(%q) = %v: a >2-label rule can never match the TLD+1 key", qname, tags)
		}
	}
	if tags := e.Match("www.google.com.", "1.2.3.4"); !tags["alive"] {
		t.Errorf("Match(www.google.com.) = %v, want the two-label rule to keep working", tags)
	}
}

// TestEngine_MatchTags_NetIPDirect pins the Round 6 D5 path: MatchTags
// consumes the client net.IP directly (no per-query String→ParseIP round
// trip) and agrees with the string-based Match on both families; a nil IP
// matches domain rules only.
func TestEngine_MatchTags_NetIPDirect(t *testing.T) {
	e := testEngine(t, []config.RuleSet{
		{Tag: "google", Type: "domain", Rule: []string{"google.com"}},
		{Tag: "corp", Type: "ip", Rule: []string{"10.0.0.0/8"}},
		{Tag: "v6", Type: "ip", Rule: []string{"2001:db8::/32"}},
	})
	for _, ip := range []string{"10.1.2.3", "192.0.2.9", "2001:db8::1", "2001:db9::1"} {
		want := e.Match("www.google.com.", ip)
		got := e.MatchTags("www.google.com.", net.ParseIP(ip))
		if len(got) != len(want) {
			t.Fatalf("MatchTags(%s) = %v, Match(%q) = %v — results diverge", ip, got, ip, want)
		}
		for tag := range want {
			if !got[tag] {
				t.Fatalf("MatchTags(%s) = %v, missing tag %q present in Match", ip, got, tag)
			}
		}
	}
	if tags := e.MatchTags("www.google.com.", nil); len(tags) != 1 || !tags["google"] {
		t.Errorf("MatchTags(nil IP) = %v, want the domain-only match", tags)
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
		// Note: multi-part TLDs (.co.uk, .com.au, etc.) are not handled —
		// see tldPlusOne godoc for rationale.
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
