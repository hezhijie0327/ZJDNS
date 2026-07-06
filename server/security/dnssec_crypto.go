package security

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"codeberg.org/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/log"
)

// IANA root zone KSK trust anchors, sourced from
// https://data.iana.org/root-anchors/root-anchors.xml
//
// Key tag 20326 (RSASHA256) — valid since 2017-02-02
// Key tag 38696 (RSASHA256) — valid since 2024-07-18 (successor)
const rootTrustAnchor20326 = ". IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="

const rootTrustAnchor38696 = ". IN DNSKEY 257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc="

// Common DNSSEC-related errors.
var (
	ErrNoRRSIG        = errors.New("no RRSIG found for rrset")
	ErrNoDNSKEY       = errors.New("no DNSKEY found for zone")
	ErrNoDS           = errors.New("no DS found for delegation")
	ErrDSMismatch     = errors.New("DS digest does not match DNSKEY")
	ErrBogusSignature = errors.New("bogus DNSSEC signature")
)

// CryptoValidator performs cryptographic DNSSEC validation using the
// miekg/dns RRSIG.Verify() and DNSKEY.ToDS() primitives. It is always active;
// the dnssec_enforce config option controls error behavior, not whether
// validation runs.
type CryptoValidator struct {
	rootKeys []*dns.DNSKEY
	cache    cache.Store
}

type rrsetKey struct {
	name   string
	rrtype uint16
}

// NewCryptoValidator creates a CryptoValidator with the IANA root trust
// anchors embedded. DNSSEC validation is always active. The cache store is
// used to persist verified zone DNSKEYs, sharing the same memory budget and
// eviction policy as DNS record cache entries.
func NewCryptoValidator(store cache.Store) *CryptoValidator {
	val := &CryptoValidator{
		cache: store,
	}
	val.loadRootTrustAnchors()
	return val
}

func (c *CryptoValidator) loadRootTrustAnchors() {
	rootAnchors := []string{rootTrustAnchor20326, rootTrustAnchor38696}
	var keys []*dns.DNSKEY

	for i, anchor := range rootAnchors {
		rr, err := dns.New(anchor)
		if err != nil {
			log.Errorf("SECURITY: failed to parse root trust anchor %d: %v", i, err)
			continue
		}
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			log.Errorf("SECURITY: root trust anchor %d is not a DNSKEY record", i)
			continue
		}
		if dnskey.Flags&dns.FlagSEP == 0 || dnskey.Flags&dns.FlagZONE == 0 {
			log.Errorf("SECURITY: root trust anchor %d missing required DNSKEY flags (SEP/ZONE)", i)
			continue
		}
		keys = append(keys, dnskey)
		log.Debugf("SECURITY: loaded root trust anchor (key tag=%d, algorithm=%s)",
			dnskey.KeyTag(), dns.AlgorithmToString[dnskey.Algorithm])
	}

	if len(keys) == 0 {
		log.Errorf("SECURITY: no valid root trust anchors loaded")
		return
	}
	c.rootKeys = keys
	log.Infof("SECURITY: initialized with %d root trust anchor(s)", len(keys))
}

// VerifyRRset verifies an RRSIG over an RRset using the given DNSKEY.
// Returns nil on success, or an error describing the failure.
func (c *CryptoValidator) VerifyRRset(rrset []dns.RR, rrsig *dns.RRSIG, dnskey *dns.DNSKEY) error {
	if rrsig == nil {
		return ErrNoRRSIG
	}
	if dnskey == nil {
		return ErrNoDNSKEY
	}

	// Check the RRSIG validity period manually (RFC 4034 §3.1.5)
	now := uint32(log.NowUnix())
	if rrsig.Inception > now || rrsig.Expiration < now {
		return fmt.Errorf("%w: RRSIG outside validity period (inception=%s, expiration=%s)",
			ErrBogusSignature, time.Unix(int64(rrsig.Inception), 0).UTC(), time.Unix(int64(rrsig.Expiration), 0).UTC())
	}

	// Verify the cryptographic signature
	if err := rrsig.Verify(dnskey, rrset, &dns.SignOption{}); err != nil {
		return fmt.Errorf("%w: %w", ErrBogusSignature, err)
	}

	return nil
}

// VerifyDelegationDS verifies that a child zone's DNSKEY matches the parent
// zone's DS record. Returns the matching DNSKEY on success.
func (c *CryptoValidator) VerifyDelegationDS(dsRecords []*dns.DS, childDNSKEYs []*dns.DNSKEY) (*dns.DNSKEY, error) {
	if len(dsRecords) == 0 {
		return nil, ErrNoDS
	}
	if len(childDNSKEYs) == 0 {
		return nil, ErrNoDNSKEY
	}

	for _, ds := range dsRecords {
		for _, dnskey := range childDNSKEYs {
			// Only KSK (SEP bit set) should match the DS
			if dnskey.Flags&dns.FlagSEP == 0 {
				continue
			}
			computedDS := dnskey.ToDS(ds.DigestType)
			if computedDS == nil {
				continue
			}
			if computedDS.KeyTag == ds.KeyTag &&
				computedDS.Algorithm == ds.Algorithm &&
				computedDS.DigestType == ds.DigestType &&
				computedDS.Digest == ds.Digest {
				log.Debugf("SECURITY: DS matched DNSKEY (key_tag=%d, alg=%s)", ds.KeyTag, dns.AlgorithmToString[ds.Algorithm])
				return dnskey, nil
			}
		}
	}

	return nil, fmt.Errorf("%w: no DNSKEY matches the provided DS records", ErrDSMismatch)
}

// SelfVerifyDNSKEY verifies that a zone's DNSKEY RRset is self-signed by the
// zone's KSK. This confirms that the DNSKEY records are authentic.
func (c *CryptoValidator) SelfVerifyDNSKEY(dnskeys []*dns.DNSKEY, dnskeyRRSIGs []*dns.RRSIG) error {
	if len(dnskeys) == 0 {
		return ErrNoDNSKEY
	}

	// Convert []*dns.DNSKEY to []dns.RR for Verify
	rrset := make([]dns.RR, len(dnskeys))
	for i, k := range dnskeys {
		rrset[i] = k
	}

	// The KSK self-signs the DNSKEY RRset. Try verifying with each KSK.
	var verified bool
	for _, rrsig := range dnskeyRRSIGs {
		for _, ksk := range dnskeys {
			if ksk.Flags&dns.FlagSEP == 0 {
				continue
			}
			if ksk.KeyTag() != rrsig.KeyTag {
				continue
			}
			if err := c.VerifyRRset(rrset, rrsig, ksk); err == nil {
				verified = true
				log.Debugf("SECURITY: self-verified zone DNSKEY (key_tag=%d)", ksk.KeyTag())
				break
			}
		}
		if verified {
			break
		}
	}

	if !verified {
		return fmt.Errorf("%w: DNSKEY self-signature verification failed", ErrBogusSignature)
	}
	return nil
}

// CollectRRSIGs collects all RRSIG records from multiple RR slices.
func CollectRRSIGs(slices ...[]dns.RR) []*dns.RRSIG {
	total := 0
	for _, rrs := range slices {
		total += len(rrs)
	}
	sigs := make([]*dns.RRSIG, 0, total)
	for _, rrs := range slices {
		for _, rr := range rrs {
			if rrsig, ok := rr.(*dns.RRSIG); ok {
				sigs = append(sigs, rrsig)
			}
		}
	}
	return sigs
}

// FindRRSIGs filters RRSIG records from a pre-collected slice, matching the
// given owner name and type covered.
func FindRRSIGs(sigs []*dns.RRSIG, ownerName string, typeCovered uint16) []*dns.RRSIG {
	if len(sigs) == 0 {
		return nil
	}
	normalized := strings.ToLower(ownerName)
	var result []*dns.RRSIG
	for _, rrsig := range sigs {
		if rrsig == nil {
			continue
		}
		if rrsig.TypeCovered == typeCovered && strings.ToLower(rrsig.Header().Name) == normalized {
			result = append(result, rrsig)
		}
	}
	return result
}

// FindDNSKEYs extracts DNSKEY records from an RR slice.
func FindDNSKEYs(rrs []dns.RR) []*dns.DNSKEY {
	var keys []*dns.DNSKEY
	for _, rr := range rrs {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, dnskey)
		}
	}
	return keys
}

// FindDS extracts DS records from an RR slice.
func FindDS(rrs []dns.RR) []*dns.DS {
	var records []*dns.DS
	for _, rr := range rrs {
		if ds, ok := rr.(*dns.DS); ok {
			records = append(records, ds)
		}
	}
	return records
}

// findNSEC extracts NSEC records from an RR slice.
func findNSEC(rrs []dns.RR) []*dns.NSEC {
	var records []*dns.NSEC
	for _, rr := range rrs {
		if nsec, ok := rr.(*dns.NSEC); ok {
			records = append(records, nsec)
		}
	}
	return records
}

// findNSEC3 extracts NSEC3 records from an RR slice.
func findNSEC3(rrs []dns.RR) []*dns.NSEC3 {
	var records []*dns.NSEC3
	for _, rr := range rrs {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			records = append(records, nsec3)
		}
	}
	return records
}

// canonicalCompare compares two domain names according to DNS canonical
// ordering per RFC 4034 section 6.1. Returns -1 if a < b, 0 if equal, 1 if a > b.
//
// DNS canonical ordering compares labels from the rightmost (TLD) label
// working leftwards. Within each label, bytes are compared lexicographically
// (case-insensitively). A name that is a suffix of another name from the
// right sorts before the longer name.
func canonicalCompare(a, b string) int {
	a = strings.ToLower(strings.TrimSuffix(a, "."))
	b = strings.ToLower(strings.TrimSuffix(b, "."))

	if a == "" && b == "" {
		return 0
	}
	if a == "" {
		return -1 // root sorts before everything
	}
	if b == "" {
		return 1
	}

	la := strings.Split(a, ".")
	lb := strings.Split(b, ".")

	// Compare from the rightmost label (TLD side) going leftwards
	i, j := len(la)-1, len(lb)-1
	for i >= 0 && j >= 0 {
		if la[i] < lb[j] {
			return -1
		}
		if la[i] > lb[j] {
			return 1
		}
		i--
		j--
	}

	// One is a suffix of the other. A shorter name (parent zone) sorts first.
	if i < 0 && j < 0 {
		return 0
	}
	if i < 0 {
		return -1 // a is shorter, so a < b
	}
	return 1 // b is shorter, so a > b
}

// isDomainInRange checks whether a domain name falls within an
// NSEC record's coverage range using DNS canonical ordering (RFC 4034 section 6.1).
//
// In the normal case (lower < upper), the name is covered if
// lower < name < upper, i.e., strictly between the NSEC owner and the Next
// Domain Name.
//
// In the wrap-around case (lower >= upper), where the NSEC covers the last
// name in the zone and wraps back to the first, the name is covered if
// lower < name OR name < upper.
func isDomainInRange(name, lower, upper string) bool {
	loName := canonicalCompare(lower, name) // lower vs name
	naUp := canonicalCompare(name, upper)   // name vs upper
	loUp := canonicalCompare(lower, upper)  // lower vs upper

	// Normal case: lower < name < upper
	if loName < 0 && naUp < 0 {
		return true
	}

	// Wrap-around case: lower >= upper, range covers everything except
	// [upper, lower]. Name is covered if > lower OR < upper.
	if loUp >= 0 {
		return loName < 0 || naUp < 0
	}

	return false
}

// IsResponseValid performs full cryptographic DNSSEC validation of a
// response. It expects the zone's verified DNSKEY to be provided.
//
// Returns (validated bool, error). If error is non-nil, validation failed.
// If validated is true, the AuthenticatedData flag may be set.
func (c *CryptoValidator) IsResponseValid(response *dns.Msg, zonename string, verifiedDNSKEYs []*dns.DNSKEY) (bool, error) {
	if response == nil || len(verifiedDNSKEYs) == 0 {
		return false, nil
	}

	// For NOERROR/NXDOMAIN responses, validate the RRSIGs on answer records
	rcode := response.Rcode
	if rcode == dns.RcodeSuccess && len(response.Answer) > 0 {
		return c.isAnswerSectionValid(response.Answer, response.Extra, verifiedDNSKEYs)
	}

	// Extract the queried name and type for denial-of-existence validation.
	// DNS servers echo the question back in the response, so it should be present.
	qname := ""
	qtype := uint16(0)
	if len(response.Question) > 0 {
		qname = response.Question[0].Header().Name
		qtype = dns.RRToType(response.Question[0])
	}

	if rcode == dns.RcodeNameError {
		return c.isNXDOMAINValid(response, qname, qtype, verifiedDNSKEYs)
	}

	// NODATA (NOERROR with no answer and NSEC)
	if rcode == dns.RcodeSuccess && len(response.Answer) == 0 {
		return c.isNODATAValid(response, qname, qtype, verifiedDNSKEYs)
	}

	return false, nil
}

func (c *CryptoValidator) isAnswerSectionValid(answer, extra []dns.RR, verifiedDNSKEYs []*dns.DNSKEY) (bool, error) {
	// Group records by owner name and type
	groups := groupRRset(answer)
	allRRSIGs := CollectRRSIGs(answer, extra)

	var anyValidated bool
	for _, group := range groups {
		if len(group) == 0 {
			continue
		}
		header := group[0].Header()
		sigs := FindRRSIGs(allRRSIGs, header.Name, dns.RRToType(group[0]))
		if len(sigs) == 0 {
			log.Debugf("SECURITY: no RRSIG for %s/%s", header.Name, dns.TypeToString[dns.RRToType(group[0])])
			continue
		}

		var groupValidated bool
		for _, sig := range sigs {
			for _, key := range verifiedDNSKEYs {
				if key.KeyTag() != sig.KeyTag {
					continue
				}
				if err := c.VerifyRRset(group, sig, key); err == nil {
					anyValidated = true
					groupValidated = true
					log.Debugf("SECURITY: validated %s/%s with key_tag=%d", header.Name, dns.TypeToString[dns.RRToType(group[0])], key.KeyTag())
					break
				}
			}
			if groupValidated {
				break
			}
		}

		// An RRset with RRSIGs whose key tags don't match any verified DNSKEY
		// indicates either a bogus signature, a zone cut (child zone keys),
		// or a cross-zone CNAME target (e.g. an A record signed by a CDN
		// zone's keys that is completely unrelated to the current zone).
		// For cross-zone records, skip the RRset — the CNAME resolver will
		// validate them against their own zone's DNSKEYs.
		if !groupValidated {
			crossZone := true
			for _, sig := range sigs {
				signer := strings.ToLower(strings.TrimSuffix(sig.SignerName, "."))
				for _, key := range verifiedDNSKEYs {
					keyZone := strings.ToLower(strings.TrimSuffix(key.Header().Name, "."))
					if signer == keyZone || strings.HasSuffix(signer, "."+keyZone) {
						crossZone = false
						break
					}
				}
				if !crossZone {
					break
				}
			}
			if crossZone {
				log.Debugf("SECURITY: skipping %s/%s — RRSIG signer is not in verified zone", header.Name, dns.TypeToString[dns.RRToType(group[0])])
				continue
			}
			return false, fmt.Errorf("%w: no matching DNSKEY for RRSIG over %s/%s (key tags in RRSIGs do not match verified zone keys)",
				ErrBogusSignature, header.Name, dns.TypeToString[dns.RRToType(group[0])])
		}
	}

	if !anyValidated && len(answer) > 0 {
		return false, errors.New("no answer RRset could be cryptographically verified")
	}
	return anyValidated, nil
}

func groupRRset(rrs []dns.RR) map[rrsetKey][]dns.RR {
	groups := make(map[rrsetKey][]dns.RR)
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		h := rr.Header()
		key := rrsetKey{name: strings.ToLower(h.Name), rrtype: dns.RRToType(rr)}
		groups[key] = append(groups[key], rr)
	}
	return groups
}

// CacheZoneKeys stores verified DNSKEYs for a zone in the unified cache.
// Keys are stored as CompactRecords in the Answer section of a CacheEntry
// so they share the same memory budget, eviction policy, and persistence
// as DNS response records.
func (c *CryptoValidator) CacheZoneKeys(zone string, keys []*dns.DNSKEY) {
	if c == nil || c.cache == nil || len(keys) == 0 {
		return
	}
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))

	// Use the minimum TTL from the DNSKEY records themselves (respecting the
	// zone operator's chosen TTL), with a 60-second floor to avoid thrashing.
	ttl := config.DefaultDNSKeyCacheTTL
	for _, k := range keys {
		if k != nil && int(k.Header().TTL) > 0 && int(k.Header().TTL) < ttl {
			ttl = int(k.Header().TTL)
		}
	}
	rrKeys := make([]dns.RR, 0, len(keys))
	for _, k := range keys {
		if k != nil {
			rrKeys = append(rrKeys, k)
		}
	}
	c.cache.Set(zone, dns.TypeDNSKEY, dns.ClassINET, nil, false, rrKeys, nil, nil, true)

}

// ZoneKeys retrieves cached verified DNSKEYs for a zone from the unified
// cache. Returns nil when the zone is not cached or the entry has expired.
func (c *CryptoValidator) ZoneKeys(zone string) []*dns.DNSKEY {
	if c == nil || c.cache == nil {
		return nil
	}
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))

	cachedEntry, found, expired := c.cache.Get(zone, dns.TypeDNSKEY, dns.ClassINET, nil, false)
	if !found || cachedEntry == nil || expired {
		return nil
	}

	// Expand CompactRecords back to dns.RR, then filter for DNSKEYs.
	// includeDNSSEC must be true — otherwise processRR strips RRSIG/NSEC/NSEC3/DNSKEY/DS.
	records := cache.ProcessRecords(cachedEntry.Answer, 0, false, true)
	return FindDNSKEYs(records)
}

// RootKeys returns the root trust anchor DNSKEYs.
func (c *CryptoValidator) RootKeys() []*dns.DNSKEY {
	return c.rootKeys
}
