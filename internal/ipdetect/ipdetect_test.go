package ipdetect

import (
	"net"
	"testing"
)

// ── validateDetectedIP ───────────────────────────────────────────────────────

func TestValidateDetectedIP(t *testing.T) {
	cases := []struct {
		ip        string
		forceIPv6 bool
		want      bool
		desc      string
	}{
		{"192.0.2.1", false, true, "public IPv4"},
		{"2001:db8::1", true, true, "public IPv6"},
		{"192.0.2.1", true, false, "IPv4 rejected for IPv6 family"},
		{"2001:db8::1", false, false, "IPv6 rejected for IPv4 family"},
		{"10.0.0.1", false, false, "private IPv4 rejected"},
		{"127.0.0.1", false, false, "loopback rejected"},
		{"::1", true, false, "IPv6 loopback rejected"},
		{"fe80::1", true, false, "link-local rejected"},
		{"0.0.0.0", false, false, "unspecified rejected"},
		{"not-an-ip", false, false, "unparseable rejected"},
	}
	for _, c := range cases {
		got := validateDetectedIP(net.ParseIP(c.ip), c.forceIPv6)
		if (got != nil) != c.want {
			t.Errorf("%s (%s, v6=%v): got %v, want found=%v", c.desc, c.ip, c.forceIPv6, got, c.want)
		}
	}
}

// ── ipFromTXT (DNS myaddr provider) ─────────────────────────────────────────

func TestIPFromTXT(t *testing.T) {
	cases := []struct {
		txts      []string
		forceIPv6 bool
		want      string
		desc      string
	}{
		{[]string{"192.0.2.1"}, false, "192.0.2.1", "plain IPv4"},
		{[]string{`"2001:db8::1"`}, true, "2001:db8::1", "quoted IPv6"},
		{[]string{`"192.129.210.214"`}, false, "192.129.210.214", "quoted IPv4 (real ns1.google.com format)"},
		{[]string{"not-an-ip", "198.51.100.7"}, false, "198.51.100.7", "skip invalid, take valid"},
		{[]string{"10.0.0.1", "192.0.2.1"}, false, "192.0.2.1", "skip private, take public"},
		{[]string{"2001:db8::1"}, false, "", "v6 answer rejected for v4 family"},
		{[]string{"junk"}, false, "", "no valid answer"},
		{nil, false, "", "empty list"},
	}
	for _, c := range cases {
		got := ipFromTXT(c.txts, c.forceIPv6)
		gotStr := ""
		if got != nil {
			gotStr = got.String()
		}
		if gotStr != c.want {
			t.Errorf("%s: got %q, want %q", c.desc, gotStr, c.want)
		}
	}
}

// ── Detector provider chain ──────────────────────────────────────────────────
