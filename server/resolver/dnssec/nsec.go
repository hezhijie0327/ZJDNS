package dnssec

import (
	"fmt"
	"slices"
	"strings"
	"zjdns/config"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
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
		return !slices.Contains(nsec.TypeBitMap, qtype)
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
