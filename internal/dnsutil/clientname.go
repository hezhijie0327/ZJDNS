package dnsutil

import "strings"

// Client-name extraction (NextDNS-style identity tokens): the "{name}"
// segment of a DoH path or the "{name}.{domain}" SNI of a TLS/QUIC listener.
// The name doubles as the ACL entry form — a non-IP string in an ACL list.

// ParseClientName validates and canonicalises a client name: 1-63 chars,
// [a-z0-9][a-z0-9-]* (case-folded).  Dots, underscores, slashes and every
// other character are rejected — a mistyped CIDR therefore fails name
// validation instead of silently becoming an ACL name.  Returns "" when the
// input is not a valid name.
func ParseClientName(s string) string {
	s = strings.ToLower(s)
	n := len(s)
	if n == 0 || n > 63 {
		return ""
	}
	for i := range n {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == n-1 { // no leading/trailing hyphen (hostname label rule)
				return ""
			}
		default:
			return ""
		}
	}
	return s
}

// ClientNameFromSNI extracts the client name from a TLS SNI value:
// "{name}.{domain}" yields the name; the bare domain, an empty SNI, or any
// other shape (multi-label prefix, invalid name) yields "".  The suffix match
// is case-insensitive (SNI is case-insensitive), matching crypto/tls, which
// lowercases ServerName on the server side.
func ClientNameFromSNI(sni, domain string) string {
	if sni == "" || domain == "" || len(sni) <= len(domain)+1 {
		return ""
	}
	if !strings.EqualFold(sni[len(sni)-len(domain):], domain) {
		return ""
	}
	sep := len(sni) - len(domain) - 1
	if sni[sep] != '.' {
		return ""
	}
	return ParseClientName(sni[:sep])
}

// ClientNameFromPath matches a DoH request path against the configured
// endpoint.  Three outcomes:
//
//	("", true)  — exactly the endpoint: no name presented
//	(name, true) — "{endpoint}/{name}" with a valid name segment
//	("", false) — anything else: the caller answers 404
//
// A trailing extra segment (or an invalid name segment) is NOT accepted —
// unknown identities must not be silently served as anonymous.
func ClientNameFromPath(path, endpoint string) (string, bool) {
	if path == endpoint {
		return "", true
	}
	rest, ok := strings.CutPrefix(path, endpoint+"/")
	if !ok || rest == "" {
		return "", false
	}
	if strings.Contains(rest, "/") {
		return "", false
	}
	name := ParseClientName(rest)
	if name == "" {
		return "", false
	}
	return name, true
}
