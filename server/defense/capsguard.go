package defense

import (
	"math/rand/v2"
)

// CapsGuard is the DNS 0x20 question-case randomization defense
// (draft-vixie-dnsext-dns0x20-00): outbound queries carry a randomly cased
// question and the responder must echo it byte-for-byte, extending the
// 16-bit transaction ID by one bit per ASCII letter.  It is stateless — a
// single pure function — and gated per-upstream via config.CapsGuard (all
// protocols; forwarded and recursive paths alike).
//
// RandomizeCase returns name with the 0x20 (case) bit of each ASCII letter
// (0x41–0x5A, 0x61–0x7A) flipped with 50% probability (§5.1).
//
// Responders are required to ignore these bits while copying the question
// byte-for-byte into the response (RFC 4343 §3: DNS case insensitivity is
// ASCII-only), so the random case pattern acts as extra transaction entropy:
// one bit per ASCII letter on top of the 16-bit ID.
//
// Non-letter octets — digits, the root/trailing dot, escaped bytes (e.g.
// \065) — are never touched; a name without ASCII letters is returned
// unchanged with no allocation.  A flip never changes the wire length, so
// randomized names can be patched in place (cached-response question echo).
func RandomizeCase(name string) string {
	// First pass: bail out without allocating when there is nothing to
	// randomize.
	hasLetter := false
	for i := 0; i < len(name); i++ {
		if isASCIILetter(name[i]) {
			hasLetter = true
			break
		}
	}
	if !hasLetter {
		return name
	}

	b := []byte(name)
	for i, c := range b {
		if isASCIILetter(c) {
			//nolint:gosec // G404: per-letter case bit — the pattern is
			// observable on the wire by design; math/rand/v2 suffices.
			if rand.IntN(2) == 1 {
				b[i] = c ^ 0x20
			}
		}
	}
	return string(b)
}

// isASCIILetter reports whether c is an ASCII letter — the only octets with
// DNS case insensitivity (RFC 4343 §3).
func isASCIILetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}
