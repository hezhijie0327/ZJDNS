package dnsutil

import "testing"

func TestParseClientName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"alice", "alice"},
		{"Alice", "alice"}, // case-folded
		{"a1-b2", "a1-b2"},
		{"a", "a"},
		{"", ""},                       // empty
		{"-lead", ""},                  // leading hyphen
		{"trail-", ""},                 // trailing hyphen
		{"under_score", ""},            // underscore invalid (hostname label)
		{"dot.ted", ""},                // dot invalid — a mistyped CIDR is not a name
		{"10.0.0.0/244", ""},           // mistyped CIDR: slash invalid
		{"192.168.1", ""},              // malformed IP: dots invalid
		{"sp ace", ""},                 // space invalid
		{string(make([]byte, 64)), ""}, // too long (and NUL bytes anyway)
	}
	for _, tt := range tests {
		if got := ParseClientName(tt.in); got != tt.want {
			t.Errorf("ParseClientName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestClientNameFromSNI(t *testing.T) {
	const domain = "dns.example.org"
	tests := []struct {
		sni  string
		want string
	}{
		{"alice.dns.example.org", "alice"},
		{"ALICE.DNS.EXAMPLE.ORG", "alice"}, // case-insensitive suffix
		{"dns.example.org", ""},            // the bare domain: no name
		{"", ""},                           // no SNI
		{"other.example.org", ""},          // different suffix
		{"a.b.dns.example.org", ""},        // multi-label prefix: not a name
		{"bad_.dns.example.org", ""},       // invalid name charset
		{"example.org", ""},                // suffix must be the full domain
	}
	for _, tt := range tests {
		if got := ClientNameFromSNI(tt.sni, domain); got != tt.want {
			t.Errorf("ClientNameFromSNI(%q, %s) = %q, want %q", tt.sni, domain, got, tt.want)
		}
	}
}

func TestClientNameFromPath(t *testing.T) {
	const endpoint = "/dns-query"
	tests := []struct {
		path string
		name string
		ok   bool
	}{
		{"/dns-query", "", true},
		{"/dns-query/alice", "alice", true},
		{"/dns-query/Alice", "alice", true},
		{"/dns-query/", "", false},            // empty segment
		{"/dns-query/alice/extra", "", false}, // deeper nesting
		{"/dns-query/bad_", "", false},        // invalid name segment
		{"/other", "", false},                 // different endpoint
	}
	for _, tt := range tests {
		name, ok := ClientNameFromPath(tt.path, endpoint)
		if name != tt.name || ok != tt.ok {
			t.Errorf("ClientNameFromPath(%q) = (%q, %v), want (%q, %v)", tt.path, name, ok, tt.name, tt.ok)
		}
	}
}
