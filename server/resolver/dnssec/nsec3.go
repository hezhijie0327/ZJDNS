// NSEC3 denial-of-existence proofs: hash-chain matching (closest encloser,
// NXDOMAIN/NODATA), opt-out handling, and name hashing.

package dnssec

import (
	"slices"
	"strings"
	"zjdns/config"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// verifyNSEC3 verifies the NSEC3 denial-of-existence proof (RFC 5155 §7–8).
// All NSEC3 records are first filtered to the RRSIG-verified subset (skipping
// ancestor delegations per RFC 6840 §4.1).  The verified subset must share
// consistent NSEC3 parameters (§7.2).  If the proof passes, the denial is
// cryptographically valid.  The verified subset is returned so callers can
// base the RFC 5155 §9.2 Opt-Out AD-suppression decision on exactly the
// records relied upon, not on unrelated NSEC3s in the response.
func (c *CryptoValidator) verifyNSEC3(authSigs []*dns.RRSIG, nsec3s []*dns.NSEC3, verifiedDNSKEYs []*dns.DNSKEY, normalizedQname string, qtype uint16, denialType string) (bool, []*dns.NSEC3) {
	verified := c.filterVerifiedNSEC3(authSigs, nsec3s, verifiedDNSKEYs, qtype)
	if len(verified) == 0 {
		return false, verified
	}
	if !nsec3ParamsConsistent(verified) {
		return false, verified
	}
	params := verified[0]
	return matchesNSEC3Denial(verified, normalizedQname, qtype, denialType, params.Hash, params.Iterations, params.Salt), verified
}

// filterVerifiedNSEC3 returns the subset of NSEC3 records whose RRSIGs verify
// against the trusted DNSKEYs, skipping ancestor delegation records.
//
// The ancestor-delegation exclusion (RFC 6840 §4.1: NS=1, SOA=0 must not
// prove non-existence BELOW the zone cut) does NOT apply to DS queries: the
// delegation's own NSEC3 is exactly the record that proves whether the DS
// RRset exists AT the zone cut. Skipping it broke no-DS NODATA proofs for
// Opt-Out zones like .com/.net.
func (c *CryptoValidator) filterVerifiedNSEC3(authSigs []*dns.RRSIG, nsec3s []*dns.NSEC3, verifiedDNSKEYs []*dns.DNSKEY, qtype uint16) []*dns.NSEC3 {
	var verified []*dns.NSEC3
	for _, nsec3 := range nsec3s {
		if qtype != dns.TypeDS && isAncestorDelegationNSEC3(nsec3) {
			continue
		}
		rrsigs := FindRRSIGs(authSigs, nsec3.Header().Name, dns.TypeNSEC3)
		if c.verifyNSEC3RRSIG(nsec3, rrsigs, verifiedDNSKEYs) {
			verified = append(verified, nsec3)
		}
	}
	return verified
}

// verifyNSEC3RRSIG verifies the RRSIG covering a single NSEC3 record against
// the trusted DNSKEYs.
func (c *CryptoValidator) verifyNSEC3RRSIG(nsec3 *dns.NSEC3, rrsigs []*dns.RRSIG, verifiedDNSKEYs []*dns.DNSKEY) bool {
	if len(rrsigs) == 0 {
		return false
	}
	rrset := []dns.RR{nsec3}
	keyTags := KeyTags(verifiedDNSKEYs)
	for _, sig := range rrsigs {
		for i, key := range verifiedDNSKEYs {
			if keyTags[i] != sig.KeyTag {
				continue
			}
			if err := c.VerifyRRset(rrset, sig, key); err != nil {
				continue
			}
			return true
		}
	}
	return false
}

// matchesNSEC3Denial checks whether the verified NSEC3 set proves the
// requested denial (RFC 5155 §8.4 NXDOMAIN, §8.5 NODATA, §8.7 wildcard NODATA).
func matchesNSEC3Denial(verified []*dns.NSEC3, normalizedQname string, qtype uint16, denialType string, hashAlg uint8, iterations uint16, salt string) bool {
	switch denialType {
	case "NXDOMAIN":
		return matchesNSEC3NXDOMAIN(verified, normalizedQname, hashAlg, iterations, salt)
	case "NODATA":
		return matchesNSEC3NODATA(verified, normalizedQname, qtype, hashAlg, iterations, salt)
	}
	return false
}

// matchesNSEC3NXDOMAIN implements RFC 5155 §8.4.
//  1. Closest-encloser proof (§8.3): findClosestEncloser validates both the CE
//     match and the next-closer cover in a single traversal.
//  2. Wildcard denial: an NSEC3 must cover H(*.closest_encloser) — a matching
//     record would mean the wildcard exists, which contradicts NXDOMAIN.
func matchesNSEC3NXDOMAIN(verified []*dns.NSEC3, qname string, hashAlg uint8, iterations uint16, salt string) bool {
	ce, ok := findClosestEncloser(verified, qname, hashAlg, iterations, salt)
	if !ok {
		return false
	}
	wildcardHash := nsec3HashName("*."+ce, hashAlg, iterations, salt)
	if wildcardHash == "" {
		return false
	}
	return hasNSEC3Covering(verified, wildcardHash)
}

// matchesNSEC3NODATA implements RFC 5155 §8.5 and §8.7.
//
// §8.5 (ordinary NODATA): an NSEC3 matching H(qname) with neither QTYPE nor
// CNAME in its TypeBitMap.  Empty non-terminals (ENT) have an empty bitmap and
// pass this check naturally.
//
// §8.7 (wildcard NODATA): when no NSEC3 matches H(qname), the qname does not
// exist.  A wildcard expansion exists at *.closest_encloser — proven by an
// NSEC3 matching H(*.closest_encloser) with QTYPE and CNAME absent.
//
// Covered-name NODATA: when neither H(qname) nor H(*.CE) has an NSEC3, the
// qname is not an NSEC3 owner — either it does not exist or it is an insecure
// delegation in Opt-Out space (RFC 5155 §9.2).  The closest-encloser walk
// already proved the next-closer cover, which is the authenticated denial;
// this is the standard case for no-DS proofs from Opt-Out zones like .com/.net.
func matchesNSEC3NODATA(verified []*dns.NSEC3, qname string, qtype uint16, hashAlg uint8, iterations uint16, salt string) bool {
	qnameHash := nsec3HashName(qname, hashAlg, iterations, salt)
	if qnameHash == "" {
		return false
	}

	// §8.5: exact match on H(qname)
	if matched := matchNSEC3(verified, qnameHash); matched != nil {
		if slices.Contains(matched.TypeBitMap, dns.TypeCNAME) {
			return false
		}
		return !slices.Contains(matched.TypeBitMap, qtype)
	}

	// §8.7: no QNAME match — try wildcard NODATA
	ce, ok := findClosestEncloser(verified, qname, hashAlg, iterations, salt)
	if !ok {
		return false
	}
	wildcardHash := nsec3HashName("*."+ce, hashAlg, iterations, salt)
	if wildcardHash == "" {
		return false
	}
	matched := matchNSEC3(verified, wildcardHash)
	if matched == nil {
		// Covered-name NODATA: no NSEC3 exists for H(qname) or H(*.CE).
		// The CE walk's next-closer cover proves no NSEC3 owner at H(qname).
		// That is only an authenticated denial when the covering record is
		// in Opt-Out space (RFC 5155 §8.6/§8.9): a missing exact-match in a
		// non-Opt-Out zone means an incomplete/corrupt proof (every
		// existing name — including empty non-terminals — has an NSEC3
		// owner there), so the NODATA must fail closed instead of being
		// accepted and negatively cached (R3-M14).
		if !nsec3CoveringHasOptOut(verified, qnameHash) {
			return false
		}
		return true
	}
	if slices.Contains(matched.TypeBitMap, dns.TypeCNAME) {
		return false
	}
	return !slices.Contains(matched.TypeBitMap, qtype)
}

// ── NSEC3 proof helpers ─────────────────────────────────────────────────────

// findClosestEncloser implements RFC 5155 §8.3.
//
// Starting from SNAME = QNAME, it walks upward label by label:
//   - If H(SNAME) matches an NSEC3: the covered flag MUST be true (set by a
//     covering NSEC3 at the previous, longer SNAME — the "next closer" cover);
//     otherwise the proof is bogus (attacker stripped the next-closer proof).
//   - If H(SNAME) has no match: set covered = hasNSEC3Covering(H(SNAME)).
//
// Returns (closestEncloser, true) on success.
func findClosestEncloser(verified []*dns.NSEC3, qname string, hashAlg uint8, iterations uint16, salt string) (string, bool) {
	sname := qname
	covered := false

	for {
		h := nsec3HashName(sname, hashAlg, iterations, salt)
		if h == "" {
			return "", false
		}

		if matchNSEC3(verified, h) != nil {
			if covered {
				return sname, true
			}
			// Matched without prior cover — bogus (RFC 5155 §8.3).
			return "", false
		}

		covered = hasNSEC3Covering(verified, h)

		next := stripLeftmostLabel(sname)
		if next == "" || next == sname {
			return "", false
		}
		sname = next
	}
}

// nsec3HashLabel returns the leftmost (hash) label of an NSEC3 owner name,
// lowercased for comparison.  Also works on bare NextDomain hashes — if there
// is no dot, the whole string is returned lowercased.
func nsec3HashLabel(owner string) string {
	before, _, ok := strings.Cut(owner, ".")
	if !ok {
		return strings.ToLower(owner)
	}
	return strings.ToLower(before)
}

// nsec3ParamsConsistent checks that all NSEC3 records share the same hash
// algorithm, iterations, and salt (RFC 5155 §7.2, §8.2).
func nsec3ParamsConsistent(nsec3s []*dns.NSEC3) bool {
	if len(nsec3s) < 2 {
		return true
	}
	first := nsec3s[0]
	for _, n := range nsec3s[1:] {
		if n.Hash != first.Hash || n.Iterations != first.Iterations || n.Salt != first.Salt {
			return false
		}
	}
	return true
}

// stripLeftmostLabel strips the leftmost label from an absolute DNS name.
// E.g., "a.b.example.com." → "b.example.com.".
// Returns "" if there are no more labels to strip.
func stripLeftmostLabel(name string) string {
	idx := strings.IndexByte(name, '.')
	if idx < 0 || idx == len(name)-1 {
		return ""
	}
	return name[idx+1:]
}

// nsec3HashName hashes a domain name using the NSEC3 parameters specified in the
// record (algorithm, iterations, salt) per RFC 5155 §5. Delegates to the
// library's dnsutil.NSEC3Name which implements the correct H(name || salt)
// ordering. Iterations are capped at config.DefaultMaxNSEC3Iterations to
// prevent DoS attacks.
func nsec3HashName(name string, hashAlg uint8, iterations uint16, salt string) string {
	if hashAlg != dns.SHA1 {
		return ""
	}
	if iterations > config.DefaultMaxNSEC3Iterations {
		// Do not silently change the hash input: hashing with a different
		// iteration count can never match the zone's NSEC3 owner names.
		// Fail closed on unsupported parameters instead.
		return ""
	}
	return dnsutil.NSEC3Name(name, salt, iterations)
}

// ── Denial-of-existence dispatch ─────────────────────────────────────────────

// isAncestorDelegationNSEC3 checks whether an NSEC3 record acts as a
// delegation cover per RFC 6840 §4.1.  An NSEC3 with NS=1, SOA=0 acts
// as an ancestor delegation — it MUST NOT prove non-existence below
// the zone cut.
func isAncestorDelegationNSEC3(nsec3 *dns.NSEC3) bool {
	hasNS := slices.Contains(nsec3.TypeBitMap, dns.TypeNS)
	hasSOA := slices.Contains(nsec3.TypeBitMap, dns.TypeSOA)
	return hasNS && !hasSOA
}

// hasOptOutInProof returns true if any NSEC3 in the proof set has Opt-Out.
func hasOptOutInProof(nsec3s []*dns.NSEC3) bool {
	for _, n := range nsec3s {
		if n.Flags&nsec3OptOutFlag != 0 {
			return true
		}
	}
	return false
}
