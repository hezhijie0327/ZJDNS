// NSEC canonical-name range helpers shared by the DNSSEC validator and the
// aggressive negative-cache synthesis path (RFC 8198).
package dnsutil

import (
	"strings"

	"codeberg.org/miekg/dns"
)

// CanonicalCompare compares two domain names per DNS canonical ordering
// (RFC 4034 §6.1). Returns -1 if a < b, 0 if equal, 1 if a > b.
func CanonicalCompare(a, b string) int {
	a = Canonical(a)
	b = Canonical(b)

	// dns.CompareName panics on the root zone "." — handle explicitly.
	if a == "." || b == "." {
		if a == b {
			return 0
		}
		if a == "." {
			return -1
		}
		return 1
	}
	return dns.CompareName(a, b)
}

// DomainInRange reports whether a domain falls within an NSEC coverage range.
func DomainInRange(name, lower, upper string) bool {
	loName := CanonicalCompare(lower, name)
	naUp := CanonicalCompare(name, upper)
	loUp := CanonicalCompare(lower, upper)

	if loName < 0 && naUp < 0 {
		return true
	}

	if loUp > 0 {
		return loName < 0 || naUp < 0
	}
	if loUp == 0 {
		// RFC 4034 §4.1: Next Domain == owner — the NSEC covers the entire
		// namespace except the owner name itself.
		return loName != 0
	}

	return false
}

// NSEC3HashLabel returns the leftmost (hash) label of an NSEC3 owner name,
// lowercased for comparison.  Also works on bare NextDomain hashes — if there
// is no dot, the whole string is returned lowercased.
func NSEC3HashLabel(owner string) string {
	before, _, ok := strings.Cut(owner, ".")
	if !ok {
		return strings.ToLower(owner)
	}
	return strings.ToLower(before)
}
