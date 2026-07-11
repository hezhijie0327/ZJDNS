package ruleset

import (
	"testing"
	"zjdns/config"
)

func TestEngine_Match_Domain(t *testing.T) {
	e, err := New([]config.RuleSet{
		{Tag: "google", Type: "domain", Rule: []string{"google.com", "*.youtube.com"}},
		{Tag: "other", Type: "domain", Rule: []string{"example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}

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
	e, err := New([]config.RuleSet{
		{Tag: "corp", Type: "ip", Rule: []string{"10.0.0.0/8", "192.168.0.0/16"}},
		{Tag: "guest", Type: "ip", Rule: []string{"0.0.0.0/0"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		ip   string
		want string
	}{
		{"10.1.2.3", "corp"},
		{"192.168.1.1", "corp"},
		{"172.16.0.1", "guest"}, // not in corp → matches 0/0
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
	e, err := New([]config.RuleSet{
		{Tag: "google", Type: "domain", Rule: []string{"google.com"}},
		{Tag: "corp", Type: "ip", Rule: []string{"10.0.0.0/8"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Query from corp IP for google.com → both tags
	tags := e.Match("google.com.", "10.1.2.3")
	if !tags["google"] || !tags["corp"] {
		t.Errorf("Match = %v, want both google and corp", tags)
	}

	// Query from public IP for google.com → only google
	tags = e.Match("google.com.", "8.8.8.8")
	if !tags["google"] || tags["corp"] {
		t.Errorf("Match = %v, want only google", tags)
	}
}

func TestEngine_HasIPTag(t *testing.T) {
	e, _ := New([]config.RuleSet{
		{Tag: "corp", Type: "ip", Rule: []string{"10.0.0.0/8"}},
		{Tag: "google", Type: "domain", Rule: []string{"google.com"}},
	})

	if !e.HasIPTag("corp") {
		t.Error("corp should be an IP tag")
	}
	if e.HasIPTag("google") {
		t.Error("google should NOT be an IP tag")
	}
	if e.HasIPTag("nonexistent") {
		t.Error("nonexistent should not be found")
	}
}

func TestEngine_MatchIP_Negation(t *testing.T) {
	e, _ := New([]config.RuleSet{
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
	// Invalid CIDRs are silently skipped (matching old cidr behavior).
	// A ruleset with only invalid CIDRs produces no IP matcher — no error.
	e, err := New([]config.RuleSet{
		{Tag: "bad", Type: "ip", Rule: []string{"not-a-cidr"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.HasIPTag("bad") {
		t.Error("tag with only invalid CIDRs should have no IP matcher")
	}
}
