package resolver

import (
	"net"
	"strings"

	"codeberg.org/miekg/dns"
)

// filterByFamily keeps only addresses of the configured family: "dual" (or
// any unknown value) keeps everything, "ipv4" drops IPv6 addresses, "ipv6"
// drops IPv4 addresses.  The caller's backing array is never mutated (callers
// reuse address lists across walk iterations).  Hostnames and non-ip:port
// entries are always kept.  Forwarding upstreams (also explicitly configured)
// are NOT filtered.
func filterByFamily(addrs []string, family string) []string {
	keepV4, keepV6 := true, true
	switch family {
	case "ipv4":
		keepV6 = false
	case "ipv6":
		keepV4 = false
	}
	if keepV4 && keepV6 {
		return addrs
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			out = append(out, a) // not an ip:port — keep
			continue
		}
		if familyFiltered(host, keepV4, keepV6) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// familyFiltered reports whether an ip:port host's address family should be
// dropped.  Hostnames are never filtered.
func familyFiltered(host string, keepV4, keepV6 bool) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	switch {
	case ip == nil:
		return false // hostname — keep
	case ip.To4() != nil:
		return !keepV4
	default:
		return !keepV6
	}
}

// responseEchoesQuestion verifies that a response echoes the query's question
// section (RFC 5452 §9.3).  Without this check, an on-path attacker could
// replay a captured signed response for ANY name in the same zone: the DNSSEC
// signatures cover the RRset, not the question, so the replayed data would
// validate and poison the cache under a different name.
func responseEchoesQuestion(resp *dns.Msg, question Question) bool {
	if resp == nil || len(resp.Question) == 0 {
		return false
	}
	q := resp.Question[0]
	return dns.EqualName(q.Header().Name, question.Name) &&
		dns.RRToType(q) == question.Qtype &&
		q.Header().Class == question.Qclass
}

// domainNamesEqual compares two strings case-insensitively, ignoring a single
// trailing dot on either string. Uses sub-slicing (no allocation) instead of
// strings.TrimSuffix (which allocates when the suffix is present).
func domainNamesEqual(a, b string) bool {
	if a != "" && a[len(a)-1] == '.' {
		a = a[:len(a)-1]
	}
	if b != "" && b[len(b)-1] == '.' {
		b = b[:len(b)-1]
	}
	return strings.EqualFold(a, b)
}
