package edns

import (
	"crypto/rand"
	"math/big"
	"strings"
)

// PerturbQnameCase randomly flips the case of each alphabetic character in a
// DNS name.  DNS names are case-insensitive (RFC 4343), so the query semantics
// are unchanged; a legitimate authoritative server echoes the query's case
// pattern, while a blind forger cannot predict it.
//
// PTR reverse-lookup names (containing ".in-addr.arpa" or ".ip6.arpa") are
// returned unchanged — some middleboxes (e.g. Cisco DNS guard) rewrite them.
func PerturbQnameCase(name string) string {
	if name == "" {
		return name
	}

	// Skip PTR queries: Cisco DNS guard boxes mangle case in reverse zones.
	if isPTRName(name) {
		return name
	}

	b := []byte(name)
	for i, ch := range b {
		if ch >= 'a' && ch <= 'z' {
			if r, err := rand.Int(rand.Reader, big.NewInt(2)); err == nil && r.Int64() == 1 {
				b[i] = ch - 32 // to upper
			}
		} else if ch >= 'A' && ch <= 'Z' {
			if r, err := rand.Int(rand.Reader, big.NewInt(2)); err == nil && r.Int64() == 1 {
				b[i] = ch + 32 // to lower
			}
		}
	}
	return string(b)
}

// IsCasePreserved checks whether the response's question name matches the
// expected (perturbed) case pattern. A legitimate server echoes the query
// name in the question section byte-for-byte.
func IsCasePreserved(queryName, responseName string) bool {
	return queryName == responseName
}

func isPTRName(name string) bool {
	return strings.HasSuffix(name, ".in-addr.arpa.") || strings.HasSuffix(name, ".ip6.arpa.")
}
