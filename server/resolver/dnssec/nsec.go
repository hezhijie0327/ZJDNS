package dnssec

import (
	"fmt"
	"slices"
	"strings"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

const nsec3OptOutFlag = 0x01

// ── NSEC denial-of-existence ─────────────────────────────────────────────────

// verifyNSEC checks whether any NSEC record in the slice cryptographically
// proves the non-existence of the queried name or type.
func (c *CryptoValidator) verifyNSEC(authSigs []*dns.RRSIG, nsecs []*dns.NSEC, verifiedDNSKEYs []*dns.DNSKEY, normalizedQname string, qtype uint16, denialType string) bool {
	for _, nsec := range nsecs {
		// RFC 6840 §4.1: ancestor delegation NSEC MUST NOT prove non-existence
		// below that zone cut.  However, an NSEC whose owner matches the
		// queried name proves NODATA AT the delegation point itself (e.g. no
		// DS for an insecure delegation — RFC 4035 §5.2), which is valid.
		// Only filter when the NSEC is from an ancestor proving below-cut
		// non-existence — i.e. the owner does not match the query name.
		if isAncestorDelegation(nsec) && nsec.Header().Name != normalizedQname {
			continue
		}
		rrsigs := FindRRSIGs(authSigs, nsec.Header().Name, dns.TypeNSEC)
		if !c.verifyNSECRecord(nsec, rrsigs, verifiedDNSKEYs, normalizedQname, qtype, denialType) {
			continue
		}
		return true
	}
	return false
}

// verifyNSECRecord verifies a single NSEC record's RRSIG and checks that it
// proves the denial.
func (c *CryptoValidator) verifyNSECRecord(nsec *dns.NSEC, rrsigs []*dns.RRSIG, verifiedDNSKEYs []*dns.DNSKEY, normalizedQname string, qtype uint16, denialType string) bool {
	if len(rrsigs) == 0 {
		return false
	}
	rrset := []dns.RR{nsec}
	for _, sig := range rrsigs {
		for _, key := range verifiedDNSKEYs {
			if key.KeyTag() != sig.KeyTag {
				continue
			}
			if err := c.VerifyRRset(rrset, sig, key); err != nil {
				continue
			}
			if matchesNSECDenial(nsec, normalizedQname, qtype, denialType) {
				return true
			}
		}
	}
	return false
}

// matchesNSECDenial checks whether an NSEC record proves the requested denial.
func matchesNSECDenial(nsec *dns.NSEC, normalizedQname string, qtype uint16, denialType string) bool {
	switch denialType {
	case "NXDOMAIN":
		// DNS names from wire are already canonical; normalisedQname is
		// pre-canonicalised by the caller.
		return isDomainInRange(normalizedQname, nsec.Header().Name, nsec.NextDomain)
	case "NODATA":
		owner := nsec.Header().Name
		if owner == normalizedQname {
			// RFC 6840 §4.3: CNAME bit set means a CNAME exists
			// at this name — NODATA is false.
			if slices.Contains(nsec.TypeBitMap, dns.TypeCNAME) {
				return false
			}
			return !slices.Contains(nsec.TypeBitMap, qtype)
		}
		// RFC 4035 §5.4 / §3.1.3.4: wildcard-expanded NODATA (QNAME does not
		// exist, *.zone exists without QTYPE) is proven by the NSEC at the
		// wildcard owner *.ancestor whose bitmap lacks QTYPE and CNAME.
		if strings.HasPrefix(owner, "*.") && dnsutil.IsBelow(owner[2:], normalizedQname) {
			if slices.Contains(nsec.TypeBitMap, dns.TypeCNAME) {
				return false
			}
			return !slices.Contains(nsec.TypeBitMap, qtype)
		}
		return false
	}
	return false
}

// ── NSEC3 denial-of-existence ────────────────────────────────────────────────

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
	for _, sig := range rrsigs {
		for _, key := range verifiedDNSKEYs {
			if key.KeyTag() != sig.KeyTag {
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
		// The CE walk's next-closer cover is the authenticated denial.
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

// matchNSEC3 returns the first NSEC3 whose owner hash label equals hash,
// or nil if none matches.
func matchNSEC3(verified []*dns.NSEC3, hash string) *dns.NSEC3 {
	h := strings.ToLower(hash)
	for _, n := range verified {
		if nsec3HashLabel(n.Header().Name) == h {
			return n
		}
	}
	return nil
}

// hasNSEC3Covering reports whether any NSEC3 in the verified set covers hash
// (i.e., hash falls inside the (owner, next) interval of that record).
func hasNSEC3Covering(verified []*dns.NSEC3, hash string) bool {
	for _, n := range verified {
		owner := nsec3HashLabel(n.Header().Name)
		next := strings.ToLower(n.NextDomain)
		if isDomainInRange(hash, owner, next) {
			return true
		}
	}
	return false
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

// isDenialOfExistenceValid verifies signed NSEC/NSEC3 records against the
// trusted DNSKEYs and checks that they cryptographically prove the non-existence
// of the queried name (NXDOMAIN) or type (NODATA). This prevents an attacker
// from satisfying validation with a validly-signed NSEC from the same zone
// that covers a different name. (RFC 4035 section 3.1.3, RFC 6840 section 5.3)
func (c *CryptoValidator) isDenialOfExistenceValid(response *dns.Msg, qname string, qtype uint16, verifiedDNSKEYs []*dns.DNSKEY, denialType string) (bool, error) {
	authSigs := CollectRRSIGs(response.Ns, response.Extra)
	normalizedQname := strings.ToLower(qname)

	if valid := c.verifyNSEC(authSigs, findNSEC(response.Ns), verifiedDNSKEYs, normalizedQname, qtype, denialType); valid {
		return true, nil
	}

	nsec3s := findNSEC3(response.Ns)
	if valid, verified := c.verifyNSEC3(authSigs, nsec3s, verifiedDNSKEYs, normalizedQname, qtype, denialType); valid {
		// RFC 5155 §9.2: an Opt-Out proof is cryptographically valid — it
		// only suppresses the AD bit. The decision is based on exactly the
		// records the proof relied upon (the RRSIG-verified subset), not on
		// unrelated Opt-Out NSEC3s in the response.
		if hasOptOutInProof(verified) {
			log.Debugf("SECURITY: NSEC3 Opt-Out proof for %s of %s — AD bit suppressed (RFC 5155 §9.2)", denialType, qname)
		}
		return true, nil
	}
	if len(nsec3s) > 0 {
		return false, fmt.Errorf("%w: NSEC3 records present but do not prove %s of %s (type=%s)", ErrBogusSignature, denialType, qname, dns.TypeToString[qtype])
	}

	return false, fmt.Errorf("%w: no signed NSEC/NSEC3 for %s", ErrBogusSignature, denialType)
}

func (c *CryptoValidator) isNXDOMAINValid(response *dns.Msg, qname string, qtype uint16, verifiedDNSKEYs []*dns.DNSKEY) (bool, error) {
	return c.isDenialOfExistenceValid(response, qname, qtype, verifiedDNSKEYs, "NXDOMAIN")
}

func (c *CryptoValidator) isNODATAValid(response *dns.Msg, qname string, qtype uint16, verifiedDNSKEYs []*dns.DNSKEY) (bool, error) {
	return c.isDenialOfExistenceValid(response, qname, qtype, verifiedDNSKEYs, "NODATA")
}

// ── Delegation / opt-out helpers ─────────────────────────────────────────────

// isAncestorDelegation checks whether an NSEC record is an ancestor
// delegation record per RFC 6840 §4.1.  An NSEC with NS=1, SOA=0, and
// signer shorter than the owner name represents a delegation point from
// an ancestor zone — it MUST NOT be used to prove non-existence below
// that zone cut.
func isAncestorDelegation(nsec *dns.NSEC) bool {
	hasNS := slices.Contains(nsec.TypeBitMap, dns.TypeNS)
	hasSOA := slices.Contains(nsec.TypeBitMap, dns.TypeSOA)
	return hasNS && !hasSOA
}

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

// CapValidatedTTL applies the RFC 4035 §5.3.3 TTL cap to validated RRsets.
// The TTL of each authenticated RRset MUST not exceed the minimum of:
//  1. The RRset's TTL as received
//  2. The RRSIG's TTL as received
//  3. The RRSIG's Original TTL field
//  4. The RRSIG's Signature Expiration minus current time
//
// This function iterates over all sections and applies the cap by mapping
// each RRSIG to its covered RRset.  RRsets without matching RRSIGs are
// left unchanged.
func CapValidatedTTL(answer, authority, additional []dns.RR) {
	now := uint32(log.NowUnix()) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
	for _, sections := range [][]dns.RR{answer, authority, additional} {
		rrsigMap := map[string][]*dns.RRSIG{}
		for _, rr := range sections {
			if sig, ok := rr.(*dns.RRSIG); ok {
				k := sig.Header().Name + "/" + dns.TypeToString[sig.TypeCovered]
				rrsigMap[k] = append(rrsigMap[k], sig)
			}
		}
		for _, rr := range sections {
			if _, isRRSIG := rr.(*dns.RRSIG); isRRSIG {
				continue
			}
			hdr := rr.Header()
			k := hdr.Name + "/" + dns.TypeToString[dns.RRToType(rr)]
			sigs := rrsigMap[k]
			if len(sigs) == 0 {
				continue
			}
			minTTL := hdr.TTL
			for _, sig := range sigs {
				if sig.Header().TTL < minTTL {
					minTTL = sig.Header().TTL
				}
				if sig.OrigTTL < minTTL {
					minTTL = sig.OrigTTL
				}
				if sig.Expiration > now {
					if r := sig.Expiration - now; r < minTTL {
						minTTL = r
					}
				}
			}
			hdr.TTL = minTTL
		}
	}
}
