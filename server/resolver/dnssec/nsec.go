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

// verifyNSEC checks whether any NSEC record in the slice cryptographically
// proves the non-existence of the queried name or type.
func (c *CryptoValidator) verifyNSEC(authSigs []*dns.RRSIG, nsecs []*dns.NSEC, verifiedDNSKEYs []*dns.DNSKEY, normalizedQname string, qtype uint16, denialType string) bool {
	for _, nsec := range nsecs {
		// RFC 6840 §4.1: ancestor delegation NSEC MUST NOT
		// prove non-existence below that zone cut.
		if isAncestorDelegation(nsec) {
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
		lower := strings.ToLower(nsec.Header().Name)
		upper := strings.ToLower(nsec.NextDomain)
		return isDomainInRange(normalizedQname, lower, upper)
	case "NODATA":
		owner := strings.ToLower(nsec.Header().Name)
		if owner != normalizedQname {
			return false
		}
		// RFC 6840 §4.3: CNAME bit set means a CNAME exists
		// at this name — NODATA is false.
		if slices.Contains(nsec.TypeBitMap, dns.TypeCNAME) {
			return false
		}
		return !slices.Contains(nsec.TypeBitMap, qtype)
	}
	return false
}

// verifyNSEC3 checks whether any NSEC3 record in the slice cryptographically
// proves the non-existence of the queried name or type.
func (c *CryptoValidator) verifyNSEC3(authSigs []*dns.RRSIG, nsec3s []*dns.NSEC3, verifiedDNSKEYs []*dns.DNSKEY, normalizedQname string, qtype uint16, denialType string) bool {
	for _, nsec3 := range nsec3s {
		// RFC 6840 §4.1: ancestor delegation NSEC3 MUST NOT
		// prove non-existence below that zone cut.
		if isAncestorDelegationNSEC3(nsec3) {
			continue
		}
		rrsigs := FindRRSIGs(authSigs, nsec3.Header().Name, dns.TypeNSEC3)
		if !c.verifyNSEC3Record(nsec3, rrsigs, verifiedDNSKEYs, normalizedQname, qtype, denialType) {
			continue
		}
		return true
	}
	return false
}

// verifyNSEC3Record verifies a single NSEC3 record's RRSIG and checks that it
// proves the denial.
func (c *CryptoValidator) verifyNSEC3Record(nsec3 *dns.NSEC3, rrsigs []*dns.RRSIG, verifiedDNSKEYs []*dns.DNSKEY, normalizedQname string, qtype uint16, denialType string) bool {
	if len(rrsigs) == 0 {
		return false
	}
	rrset := []dns.RR{nsec3}
	hashedQname := nsec3HashName(normalizedQname, nsec3.Hash, nsec3.Iterations, nsec3.Salt)
	for _, sig := range rrsigs {
		for _, key := range verifiedDNSKEYs {
			if key.KeyTag() != sig.KeyTag {
				continue
			}
			if err := c.VerifyRRset(rrset, sig, key); err != nil {
				continue
			}
			if matchesNSEC3Denial(nsec3, hashedQname, qtype, denialType) {
				return true
			}
		}
	}
	return false
}

// matchesNSEC3Denial checks whether an NSEC3 record proves the requested denial.
func matchesNSEC3Denial(nsec3 *dns.NSEC3, hashedQname string, qtype uint16, denialType string) bool {
	switch denialType {
	case "NXDOMAIN":
		owner := strings.ToLower(nsec3.Header().Name)
		next := strings.ToLower(nsec3.NextDomain)
		return isDomainInRange(hashedQname, owner, next)
	case "NODATA":
		owner := strings.ToLower(nsec3.Header().Name)
		if owner != hashedQname {
			return false
		}
		// RFC 6840 §4.3: same CNAME check as NSEC.
		if slices.Contains(nsec3.TypeBitMap, dns.TypeCNAME) {
			return false
		}
		return !slices.Contains(nsec3.TypeBitMap, qtype)
	}
	return false
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
		iterations = config.DefaultMaxNSEC3Iterations
	}
	return dnsutil.NSEC3Name(name, salt, iterations)
}

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
	if valid := c.verifyNSEC3(authSigs, nsec3s, verifiedDNSKEYs, normalizedQname, qtype, denialType); valid {
		// RFC 5155 §9.2: Opt-Out NSEC3 proofs suppress AD bit.
		if hasOptOutInProof(nsec3s) {
			return false, fmt.Errorf("NSEC3 Opt-Out proof for %s of %s — AD bit suppressed (RFC 5155 §9.2)", denialType, qname)
		}

		return true, nil
	}
	if len(nsec3s) > 0 {
		return false, fmt.Errorf("NSEC3 records present but do not prove %s of %s (type=%s)", denialType, qname, dns.TypeToString[qtype])
	}

	return false, fmt.Errorf("no signed NSEC/NSEC3 for %s", denialType)
}

func (c *CryptoValidator) isNXDOMAINValid(response *dns.Msg, qname string, qtype uint16, verifiedDNSKEYs []*dns.DNSKEY) (bool, error) {
	return c.isDenialOfExistenceValid(response, qname, qtype, verifiedDNSKEYs, "NXDOMAIN")
}

func (c *CryptoValidator) isNODATAValid(response *dns.Msg, qname string, qtype uint16, verifiedDNSKEYs []*dns.DNSKEY) (bool, error) {
	return c.isDenialOfExistenceValid(response, qname, qtype, verifiedDNSKEYs, "NODATA")
}

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
		if n.Flags&uint8(0x01) != 0 {
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
