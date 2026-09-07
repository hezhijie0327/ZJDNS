package dnssec

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

const nsec3OptOutFlag = 0x01

// ── NSEC denial-of-existence ─────────────────────────────────────────────────

// verifyNSEC checks whether any NSEC record in the slice cryptographically
// proves the non-existence of the queried name or type.  The RRSIG-verified
// subset is returned alongside the verdict — RFC 8198 aggressive negative
// caching may only index individually verified NSEC records.
func (c *CryptoValidator) verifyNSEC(authSigs []*dns.RRSIG, nsecs []*dns.NSEC, verifiedDNSKEYs []*dns.DNSKEY, normalizedQname string, qtype uint16, denialType string) ([]*dns.NSEC, bool) {
	// Verify signatures once and collect the whole verified set — the
	// NXDOMAIN verdict is set-level: RFC 4035 §5.4's wildcard proof may be
	// carried by a different NSEC than the one covering the qname.
	verified := make([]*dns.NSEC, 0, len(nsecs))
	for _, nsec := range nsecs {
		// RFC 6840 §4.1: ancestor delegation NSEC MUST NOT prove non-existence
		// below that zone cut.  However, an NSEC whose owner matches the
		// queried name proves NODATA AT the delegation point itself (e.g. no
		// DS for an insecure delegation — RFC 4035 §5.2), which is valid.
		// Only filter when the NSEC is from an ancestor proving below-cut
		// non-existence — i.e. the owner does not match the query name.
		// Case-insensitive compare: NSEC owner names come from zone files
		// that may store mixed case (legal per RFC 4343), while
		// normalizedQname is lowercased — a byte compare would wrongly
		// filter the ancestor delegation NSEC or fail the NODATA match.
		if isAncestorDelegation(nsec, authSigs) && !dns.EqualName(nsec.Header().Name, normalizedQname) {
			continue
		}
		rrsigs := FindRRSIGs(authSigs, nsec.Header().Name, dns.TypeNSEC)
		if !c.verifyNSECsig(nsec, rrsigs, verifiedDNSKEYs) {
			continue
		}
		verified = append(verified, nsec)
	}
	if denialType == "NXDOMAIN" {
		return verified, nsecProvesNXDOMAIN(verified, normalizedQname)
	}
	for _, nsec := range verified {
		if matchesNSECDenial(nsec, normalizedQname, qtype, denialType) {
			return verified, true
		}
	}
	return verified, false
}

// nsecProvesNXDOMAIN implements RFC 4035 §5.4 over the whole verified NSEC
// set: (1) an NSEC covering the qname proves it does not exist, and (2) an
// NSEC covering "*."+closest-encloser proves no wildcard could have matched
// — without (2), a replayed covering NSEC from a zone that DOES have a
// matching wildcard would wrongly validate NXDOMAIN. The closest encloser
// is the longest common ancestor of the covering interval's endpoints; when
// the covering NSEC also spans the wildcard it serves as its own proof.
func nsecProvesNXDOMAIN(verified []*dns.NSEC, qname string) bool {
	for _, nsec := range verified {
		owner, next := nsec.Header().Name, nsec.NextDomain
		if !isDomainInRange(qname, owner, next) {
			continue
		}
		wildcard := "*." + commonAncestor(owner, next)
		if isDomainInRange(wildcard, owner, next) {
			return true
		}
		for _, other := range verified {
			if isDomainInRange(wildcard, other.Header().Name, other.NextDomain) {
				return true
			}
		}
	}
	return false
}

// commonAncestor returns the longest common suffix (label-wise) of two
// domain names, canonicalized — for a covering NSEC interval this is the
// closest encloser of everything inside the gap.
func commonAncestor(a, b string) string {
	la := dnsutil.Split(dnsutil.Canonical(a))
	lb := dnsutil.Split(dnsutil.Canonical(b))
	i, j := len(la)-1, len(lb)-1
	for i >= 0 && j >= 0 && la[i] == lb[j] {
		i--
		j--
	}
	// No shared label at all (cross-zone garbage) — the root.
	suffix := la[i+1:]
	if len(suffix) == 0 {
		return "."
	}
	var sb strings.Builder
	for _, l := range suffix {
		sb.WriteString(l)
		sb.WriteByte('.')
	}
	return sb.String()
}

// verifyNSECsig cryptographically verifies a single NSEC RRset against the
// zone keys — deliberately match-free: for NXDOMAIN the covering record and
// the wildcard proof may be different NSECs, so membership in the verified
// set must not depend on matching the queried name.
func (c *CryptoValidator) verifyNSECsig(nsec *dns.NSEC, rrsigs []*dns.RRSIG, verifiedDNSKEYs []*dns.DNSKEY) bool {
	if len(rrsigs) == 0 {
		return false
	}
	rrset := []dns.RR{nsec}
	keyTags := KeyTags(verifiedDNSKEYs)
	for _, sig := range rrsigs {
		for i, key := range verifiedDNSKEYs {
			if keyTags[i] != sig.KeyTag {
				continue
			}
			if err := c.VerifyRRset(rrset, sig, key); err == nil {
				return true
			}
		}
	}
	return false
}

// ProvesNoDSAtDelegation checks the shape an authenticated no-DS denial
// must have at a delegation point when the denial carries a record AT the
// child name: that NSEC/NSEC3 must show the NS bit (the delegation exists)
// without DS (RFC 4035 §5.2) — an ordinary-name NODATA must not mark the
// delegation insecure. When NO record matches the child name the name is
// covered instead: in NSEC3 Opt-Out space that IS the insecure-delegation
// proof (RFC 5155 §9 — opt-out delegations have no NSEC3 of their own), and
// IsResponseValid has already authenticated the covering chain, so the
// denial is accepted as-is. Signature validity is the caller's concern.
func ProvesNoDSAtDelegation(response *dns.Msg, child string) bool {
	child = strings.ToLower(dnsutil.Fqdn(child))
	for _, rr := range response.Ns {
		switch n := rr.(type) {
		case *dns.NSEC:
			if dns.EqualName(n.Header().Name, child) {
				return slices.Contains(n.TypeBitMap, dns.TypeNS) &&
					!slices.Contains(n.TypeBitMap, dns.TypeDS)
			}
		case *dns.NSEC3:
			hash := nsec3HashName(child, n.Hash, n.Iterations, n.Salt)
			if hash == "" {
				continue
			}
			if nsec3HashLabel(n.Header().Name) == strings.ToLower(hash) {
				return slices.Contains(n.TypeBitMap, dns.TypeNS) &&
					!slices.Contains(n.TypeBitMap, dns.TypeDS)
			}
		}
	}
	// No record at the child name — covered (Opt-Out) space: the
	// authenticated covering denial from IsResponseValid suffices.
	return true
}

// HasCompactNXNAME reports whether the response carries the RFC 9824 NXNAME
// signal in any NSEC/NSEC3 type bitmap: the authority returned a compact
// NODATA (NOERROR, empty answer) for a name that does not exist.  Per §5.1
// ("Signaled Response Code Restoration") the resolver should restore the
// NXDOMAIN semantic for such responses.
func HasCompactNXNAME(response *dns.Msg) bool {
	for _, rr := range response.Ns {
		switch nsec := rr.(type) {
		case *dns.NSEC:
			if slices.Contains(nsec.TypeBitMap, dns.TypeNXNAME) {
				return true
			}
		case *dns.NSEC3:
			if slices.Contains(nsec.TypeBitMap, dns.TypeNXNAME) {
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
		if dns.EqualName(owner, normalizedQname) {
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

// nsec3CoveringHasOptOut reports whether the NSEC3 covering hash carries the
// Opt-Out flag (RFC 5155 §6.1 bit 0x01).  Used by covered-name NODATA
// validation — only Opt-Out space may lack an exact-match NSEC3 for a name
// that exists (RFC 5155 §8.6).
func nsec3CoveringHasOptOut(verified []*dns.NSEC3, hash string) bool {
	for _, n := range verified {
		owner := nsec3HashLabel(n.Header().Name)
		next := strings.ToLower(n.NextDomain)
		if isDomainInRange(hash, owner, next) {
			return n.Flags&nsec3OptOutFlag != 0
		}
	}
	return false
}

// isDenialOfExistenceValid verifies signed NSEC/NSEC3 records against the
// trusted DNSKEYs and checks that they cryptographically prove the non-existence
// of the queried name (NXDOMAIN) or type (NODATA). This prevents an attacker
// from satisfying validation with a validly-signed NSEC from the same zone
// that covers a different name. (RFC 4035 section 5.4, RFC 6840 section 4.1)
//
// proof carries the RRSIG-verified NSEC/NSEC3 records the denial rests on —
// RFC 8198 aggressive negative caching indexes only these, never the raw
// authority section (which may hold unverified extras).
func (c *CryptoValidator) isDenialOfExistenceValid(response *dns.Msg, qname string, qtype uint16, verifiedDNSKEYs []*dns.DNSKEY, denialType string) (validated, adSuppressed bool, proof []dns.RR, err error) {
	authSigs := CollectRRSIGs(response.Ns, response.Extra)
	normalizedQname := strings.ToLower(qname)

	verifiedNSEC, valid := c.verifyNSEC(authSigs, findNSEC(response.Ns), verifiedDNSKEYs, normalizedQname, qtype, denialType)
	if valid {
		return true, false, asProofRRs(verifiedNSEC), nil
	}

	nsec3s := findNSEC3(response.Ns)
	verifiedNSEC3, valid := c.verifyNSEC3(authSigs, nsec3s, verifiedDNSKEYs, normalizedQname, qtype, denialType)
	if valid {
		// RFC 5155 §9.2: an Opt-Out proof is cryptographically valid — the
		// validator SHOULD NOT set the AD bit for such a response. The
		// decision is based on exactly the records the proof relied upon
		// (the RRSIG-verified subset), not on unrelated Opt-Out NSEC3s in
		// the response.
		if hasOptOutInProof(verifiedNSEC3) {
			log.Debugf("SECURITY: NSEC3 Opt-Out proof for %s of %s — AD suppressed (RFC 5155 §9.2)", denialType, qname)
			return true, true, asProofRRs(verifiedNSEC3), nil
		}
		return true, false, asProofRRs(verifiedNSEC3), nil
	}
	if len(nsec3s) > 0 {
		return false, false, nil, fmt.Errorf("%w: NSEC3 records present but do not prove %s of %s (type=%s)", ErrMissingNSEC, denialType, qname, dns.TypeToString[qtype])
	}

	return false, false, nil, fmt.Errorf("%w: no signed NSEC/NSEC3 for %s", ErrMissingNSEC, denialType)
}

func (c *CryptoValidator) isNXDOMAINValid(response *dns.Msg, qname string, qtype uint16, verifiedDNSKEYs []*dns.DNSKEY) (validated, adSuppressed bool, proof []dns.RR, err error) {
	return c.isDenialOfExistenceValid(response, qname, qtype, verifiedDNSKEYs, "NXDOMAIN")
}

func (c *CryptoValidator) isNODATAValid(response *dns.Msg, qname string, qtype uint16, verifiedDNSKEYs []*dns.DNSKEY) (validated, adSuppressed bool, proof []dns.RR, err error) {
	return c.isDenialOfExistenceValid(response, qname, qtype, verifiedDNSKEYs, "NODATA")
}

// asProofRRs widens a typed verified NSEC/NSEC3 slice to the record-slice
// form carried on QueryResult.DenialProof.
func asProofRRs[T dns.RR](verified []T) []dns.RR {
	if len(verified) == 0 {
		return nil
	}
	proof := make([]dns.RR, len(verified))
	for i, rr := range verified {
		proof[i] = rr
	}
	return proof
}

// ── Delegation / opt-out helpers ─────────────────────────────────────────────

// isAncestorDelegation checks whether an NSEC record is an ancestor
// delegation record per RFC 6840 §4.1.  An NSEC with NS=1, SOA=0, and
// signer shorter than the owner name represents a delegation point from
// an ancestor zone — it MUST NOT be used to prove non-existence below
// that zone cut.
func isAncestorDelegation(nsec *dns.NSEC, authSigs []*dns.RRSIG) bool {
	if !isAncestorDelegationBitmap(nsec) {
		return false
	}
	// RFC 6840 §4.1 third condition: an NSEC is an ancestor-delegation NSEC
	// only when its RRSIG was signed ABOVE the owner (signer strictly
	// shorter). An NS-without-SOA NSEC signed by its own zone is not an
	// ancestor delegation and may still prove non-existence — without this
	// condition the filter is over-aggressive and turns valid proofs into
	// false bogus.
	owner := dnsutil.Fqdn(nsec.Header().Name)
	for _, sig := range authSigs {
		if dns.EqualName(sig.SignerName, owner) {
			return false
		}
		if dnsutil.IsBelow(dnsutil.Fqdn(sig.SignerName), owner) {
			return true
		}
	}
	return false
}

func isAncestorDelegationBitmap(nsec *dns.NSEC) bool {
	hasNS := slices.Contains(nsec.TypeBitMap, dns.TypeNS)
	hasSOA := slices.Contains(nsec.TypeBitMap, dns.TypeSOA)
	return hasNS && !hasSOA
}

// nsecRRsetKey builds a canonical RRset identity for TTL capping. Mirror of
// server/resolver/rrsetKey (same package layout would share it): RFC 3597
// unknown types have no entry in dns.TypeToString and would otherwise
// collapse distinct RRsets into a single "name/" key, and raw owner names
// would not match RRSIGs that differ from the data record only in case.
// Callers must pass the name already canonicalized (once per section).
func nsecRRsetKey(name string, typ uint16) string {
	return name + "/" + strconv.Itoa(int(typ))
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
		// Canonicalize each owner name once per section — dnsutil.Canonical
		// allocates (strings.Map), and the same name is keyed twice per RRset
		// below.
		canonName := make(map[string]string)
		canon := func(name string) string {
			if c, ok := canonName[name]; ok {
				return c
			}
			c := dnsutil.Canonical(name)
			canonName[name] = c
			return c
		}
		rrsigMap := map[string][]*dns.RRSIG{}
		for _, rr := range sections {
			if sig, ok := rr.(*dns.RRSIG); ok {
				k := nsecRRsetKey(canon(sig.Header().Name), sig.TypeCovered)
				rrsigMap[k] = append(rrsigMap[k], sig)
			}
		}
		for _, rr := range sections {
			if _, isRRSIG := rr.(*dns.RRSIG); isRRSIG {
				continue
			}
			hdr := rr.Header()
			k := nsecRRsetKey(canon(hdr.Name), dns.RRToType(rr))
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
