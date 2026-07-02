package security

import (
	"strings"

	"github.com/miekg/dns"
)

// verifyNSEC checks whether any NSEC record in the slice cryptographically
// proves the non-existence of the queried name or type.
func (c *CryptoValidator) verifyNSEC(authSigs []*dns.RRSIG, nsecs []*dns.NSEC, verifiedDNSKEYs []*dns.DNSKEY, normalizedQname string, qtype uint16, denialType string) bool {
	for _, nsec := range nsecs {
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
		for _, t := range nsec.TypeBitMap {
			if t == qtype {
				return false
			}
		}
		return true
	}
	return false
}

// verifyNSEC3 checks whether any NSEC3 record in the slice cryptographically
// proves the non-existence of the queried name or type.
func (c *CryptoValidator) verifyNSEC3(authSigs []*dns.RRSIG, nsec3s []*dns.NSEC3, verifiedDNSKEYs []*dns.DNSKEY, normalizedQname string, qtype uint16, denialType string) bool {
	for _, nsec3 := range nsec3s {
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
		for _, t := range nsec3.TypeBitMap {
			if t == qtype {
				return false
			}
		}
		return true
	}
	return false
}
