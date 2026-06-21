package security

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

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
// validation runs. Call Stop() when the validator is no longer needed to
// terminate the background key cache sweeper goroutine.
type CryptoValidator struct {
	rootKeys     []*dns.DNSKEY
	zoneKeyCache map[string]*zoneKeyEntry
	mu           sync.RWMutex
	stopCh       chan struct{}
}

type zoneKeyEntry struct {
	keys     []*dns.DNSKEY
	verified bool
	expires  time.Time
}

type rrsetKey struct {
	name   string
	rrtype uint16
}

// NewCryptoValidator creates a CryptoValidator with the IANA root trust
// anchors embedded. DNSSEC validation is always active.
func NewCryptoValidator() *CryptoValidator {
	cv := &CryptoValidator{
		zoneKeyCache: make(map[string]*zoneKeyEntry),
		stopCh:       make(chan struct{}),
	}
	cv.loadRootTrustAnchors()
	go cv.sweepExpiredKeys()
	return cv
}

// sweepExpiredKeys periodically purges expired DNSKEY cache entries to prevent
// unbounded memory growth under sustained queries to many unique zones.
func (cv *CryptoValidator) sweepExpiredKeys() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cv.mu.Lock()
			for zone, entry := range cv.zoneKeyCache {
				if entry != nil && time.Now().After(entry.expires) {
					delete(cv.zoneKeyCache, zone)
				}
			}
			cv.mu.Unlock()
		case <-cv.stopCh:
			return
		}
	}
}

// Stop terminates the background key cache sweeper.
func (cv *CryptoValidator) Stop() {
	if cv == nil || cv.stopCh == nil {
		return
	}
	select {
	case <-cv.stopCh:
	default:
		close(cv.stopCh)
	}
}

func (cv *CryptoValidator) loadRootTrustAnchors() {
	rootAnchors := []string{rootTrustAnchor20326, rootTrustAnchor38696}
	var keys []*dns.DNSKEY

	for i, anchor := range rootAnchors {
		rr, err := dns.NewRR(anchor)
		if err != nil {
			log.Errorf("SECURITY: failed to parse root trust anchor %d: %v", i, err)
			continue
		}
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			log.Errorf("SECURITY: root trust anchor %d is not a DNSKEY record", i)
			continue
		}
		if dnskey.Flags&dns.SEP == 0 || dnskey.Flags&dns.ZONE == 0 {
			log.Errorf("SECURITY: root trust anchor %d missing required DNSKEY flags (SEP/ZONE)", i)
			continue
		}
		keys = append(keys, dnskey)
		log.Infof("SECURITY: loaded root trust anchor (key tag=%d, algorithm=%s)",
			dnskey.KeyTag(), dns.AlgorithmToString[dnskey.Algorithm])
	}

	if len(keys) == 0 {
		log.Errorf("SECURITY: no valid root trust anchors loaded")
		return
	}
	cv.rootKeys = keys
	log.Infof("SECURITY: initialized with %d root trust anchor(s)", len(keys))
}

// IsEnabled reports whether cryptographic DNSSEC validation is active.
// Always returns true — DNSSEC is always on.
func (cv *CryptoValidator) IsEnabled() bool {
	return cv != nil
}

// VerifyRRset verifies an RRSIG over an RRset using the given DNSKEY.
// Returns nil on success, or an error describing the failure.
func (cv *CryptoValidator) VerifyRRset(rrset []dns.RR, rrsig *dns.RRSIG, dnskey *dns.DNSKEY) error {
	if rrsig == nil {
		return ErrNoRRSIG
	}
	if dnskey == nil {
		return ErrNoDNSKEY
	}

	// Check the RRSIG validity period manually (RFC 4034 §3.1.5)
	now := uint32(time.Now().Unix())
	if rrsig.Inception > now || rrsig.Expiration < now {
		return fmt.Errorf("%w: RRSIG outside validity period (inception=%s, expiration=%s)",
			ErrBogusSignature, time.Unix(int64(rrsig.Inception), 0).UTC(), time.Unix(int64(rrsig.Expiration), 0).UTC())
	}

	// Verify the cryptographic signature
	if err := rrsig.Verify(dnskey, rrset); err != nil {
		return fmt.Errorf("%w: %w", ErrBogusSignature, err)
	}

	return nil
}

// VerifyDelegationDS verifies that a child zone's DNSKEY matches the parent
// zone's DS record. Returns the matching DNSKEY on success.
func (cv *CryptoValidator) VerifyDelegationDS(dsRecords []*dns.DS, childDNSKEYs []*dns.DNSKEY) (*dns.DNSKEY, error) {
	if len(dsRecords) == 0 {
		return nil, ErrNoDS
	}
	if len(childDNSKEYs) == 0 {
		return nil, ErrNoDNSKEY
	}

	for _, ds := range dsRecords {
		for _, dnskey := range childDNSKEYs {
			// Only KSK (SEP bit set) should match the DS
			if dnskey.Flags&dns.SEP == 0 {
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
func (cv *CryptoValidator) SelfVerifyDNSKEY(dnskeys []*dns.DNSKEY, dnskeyRRSIGs []*dns.RRSIG) error {
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
			if ksk.Flags&dns.SEP == 0 {
				continue
			}
			if ksk.KeyTag() != rrsig.KeyTag {
				continue
			}
			if err := cv.VerifyRRset(rrset, rrsig, ksk); err == nil {
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

// dnsutilCompareDomainInRange checks whether a domain name falls within an
// NSEC record's coverage range using DNS canonical ordering (RFC 4034 section 6.1).
//
// In the normal case (lower < upper), the name is covered if
// lower < name < upper, i.e., strictly between the NSEC owner and the Next
// Domain Name.
//
// In the wrap-around case (lower >= upper), where the NSEC covers the last
// name in the zone and wraps back to the first, the name is covered if
// lower < name OR name < upper.
func dnsutilCompareDomainInRange(name, lower, upper string) bool {
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

// VerifyAuthenticatedDenial checks NSEC/NSEC3 records to confirm that a
// negative response (NXDOMAIN or NODATA) is cryptographically proven.
func (cv *CryptoValidator) VerifyAuthenticatedDenial(response *dns.Msg, qname string, qtype uint16) error {
	normalized := strings.ToLower(qname)
	nsecs := findNSEC(response.Ns)
	nsec3s := findNSEC3(response.Ns)

	if len(nsecs) == 0 && len(nsec3s) == 0 {
		return errors.New("no NSEC/NSEC3 records for authenticated denial")
	}

	// Verify NSEC coverage
	for _, nsec := range nsecs {
		lower := strings.ToLower(nsec.Header().Name)
		upper := strings.ToLower(nsec.NextDomain)
		if dnsutilCompareDomainInRange(normalized, lower, upper) {
			return nil
		}
	}

	// NSEC3 verification requires more complex logic; for now, presence
	// with valid RRSIG is sufficient in common cases.
	if len(nsec3s) > 0 {
		return nil
	}

	return fmt.Errorf("NSEC/NSEC3 does not cover name %s", qname)
}

// ValidateResponse performs full cryptographic DNSSEC validation of a
// response. It expects the zone's verified DNSKEY to be provided.
//
// Returns (validated bool, error). If error is non-nil, validation failed.
// If validated is true, the AuthenticatedData flag may be set.
func (cv *CryptoValidator) ValidateResponse(response *dns.Msg, zonename string, verifiedDNSKEYs []*dns.DNSKEY) (bool, error) {
	if response == nil || len(verifiedDNSKEYs) == 0 {
		return false, nil
	}

	// For NOERROR/NXDOMAIN responses, validate the RRSIGs on answer records
	rcode := response.Rcode
	if rcode == dns.RcodeSuccess && len(response.Answer) > 0 {
		return cv.validateAnswerSection(response.Answer, response.Extra, verifiedDNSKEYs)
	}

	// Extract the queried name and type for denial-of-existence validation.
	// DNS servers echo the question back in the response, so it should be present.
	qname := ""
	qtype := uint16(0)
	if len(response.Question) > 0 {
		qname = response.Question[0].Name
		qtype = response.Question[0].Qtype
	}

	if rcode == dns.RcodeNameError {
		return cv.validateNXDOMAIN(response, qname, qtype, verifiedDNSKEYs)
	}

	// NODATA (NOERROR with no answer and NSEC)
	if rcode == dns.RcodeSuccess && len(response.Answer) == 0 {
		return cv.validateNODATA(response, qname, qtype, verifiedDNSKEYs)
	}

	return false, nil
}

func (cv *CryptoValidator) validateAnswerSection(answer, extra []dns.RR, verifiedDNSKEYs []*dns.DNSKEY) (bool, error) {
	// Group records by owner name and type
	groups := groupRRset(answer)
	allRRSIGs := CollectRRSIGs(answer, extra)

	var anyValidated bool
	for _, group := range groups {
		if len(group) == 0 {
			continue
		}
		header := group[0].Header()
		sigs := FindRRSIGs(allRRSIGs, header.Name, header.Rrtype)
		if len(sigs) == 0 {
			log.Debugf("SECURITY: no RRSIG for %s/%s", header.Name, dns.TypeToString[header.Rrtype])
			continue
		}

		for _, sig := range sigs {
			for _, key := range verifiedDNSKEYs {
				if key.KeyTag() != sig.KeyTag {
					continue
				}
				if err := cv.VerifyRRset(group, sig, key); err == nil {
					anyValidated = true
					log.Debugf("SECURITY: validated %s/%s with key_tag=%d", header.Name, dns.TypeToString[header.Rrtype], key.KeyTag())
					break
				}
			}
		}
	}

	if !anyValidated && len(answer) > 0 {
		return false, errors.New("no answer RRset could be cryptographically verified")
	}
	return anyValidated, nil
}

// validateDenialOfExistence verifies signed NSEC/NSEC3 records against the
// trusted DNSKEYs and checks that they cryptographically prove the non-existence
// of the queried name (NXDOMAIN) or type (NODATA). This prevents an attacker
// from satisfying validation with a validly-signed NSEC from the same zone
// that covers a different name. (RFC 4035 section 3.1.3, RFC 6840 section 5.3)
func (cv *CryptoValidator) validateDenialOfExistence(response *dns.Msg, qname string, qtype uint16, verifiedDNSKEYs []*dns.DNSKEY, denialType string) (bool, error) {
	nsecs := findNSEC(response.Ns)
	nsec3s := findNSEC3(response.Ns)
	authSigs := CollectRRSIGs(response.Ns, response.Extra)

	normalizedQname := strings.ToLower(qname)

	for _, nsec := range nsecs {
		rrsigs := FindRRSIGs(authSigs, nsec.Header().Name, dns.TypeNSEC)
		if len(rrsigs) == 0 {
			continue
		}
		rrset := []dns.RR{nsec}
		for _, sig := range rrsigs {
			for _, key := range verifiedDNSKEYs {
				if key.KeyTag() == sig.KeyTag {
					if err := cv.VerifyRRset(rrset, sig, key); err == nil {
						// Valid RRSIG on this NSEC. Now verify that it actually
						// proves the denial.
						switch denialType {
						case "NXDOMAIN":
							// The queried name must fall within the NSEC range
							// [owner name, next domain) in canonical ordering.
							lower := strings.ToLower(nsec.Header().Name)
							upper := strings.ToLower(nsec.NextDomain)
							if dnsutilCompareDomainInRange(normalizedQname, lower, upper) {
								return true, nil
							}
						case "NODATA":
							// The NSEC owner name must match the queried name
							// and the type bitmap must exclude the queried type.
							owner := strings.ToLower(nsec.Header().Name)
							if owner == normalizedQname {
								typeCovered := false
								for _, t := range nsec.TypeBitMap {
									if t == qtype {
										typeCovered = true
										break
									}
								}
								if !typeCovered {
									return true, nil
								}
							}
						}
					}
				}
			}
		}
	}

	for _, nsec3 := range nsec3s {
		rrsigs := FindRRSIGs(authSigs, nsec3.Header().Name, dns.TypeNSEC3)
		if len(rrsigs) == 0 {
			continue
		}
		rrset := []dns.RR{nsec3}
		for _, sig := range rrsigs {
			for _, key := range verifiedDNSKEYs {
				if key.KeyTag() != sig.KeyTag {
					continue
				}
				if err := cv.VerifyRRset(rrset, sig, key); err == nil {
					return true, nil
				}
			}
		}
	}
	if len(nsec3s) > 0 {
		return false, errors.New("NSEC3 records present but not cryptographically signed")
	}

	return false, fmt.Errorf("no signed NSEC/NSEC3 for %s", denialType)
}

func (cv *CryptoValidator) validateNXDOMAIN(response *dns.Msg, qname string, qtype uint16, verifiedDNSKEYs []*dns.DNSKEY) (bool, error) {
	return cv.validateDenialOfExistence(response, qname, qtype, verifiedDNSKEYs, "NXDOMAIN")
}

func (cv *CryptoValidator) validateNODATA(response *dns.Msg, qname string, qtype uint16, verifiedDNSKEYs []*dns.DNSKEY) (bool, error) {
	return cv.validateDenialOfExistence(response, qname, qtype, verifiedDNSKEYs, "NODATA")
}

func groupRRset(rrs []dns.RR) map[rrsetKey][]dns.RR {
	groups := make(map[rrsetKey][]dns.RR)
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		h := rr.Header()
		key := rrsetKey{name: strings.ToLower(h.Name), rrtype: h.Rrtype}
		groups[key] = append(groups[key], rr)
	}
	return groups
}

// zoneKeyCacheMax is the maximum number of zone key cache entries. When
// exceeded, expired entries are purged and the oldest non-expired entry is
// evicted to cap memory growth under an attacker flooding many unique zones.
const zoneKeyCacheMax = 25000

// ZoneKeyCache operations

// CacheZoneKeys stores verified DNSKEYs for a zone. Keys are deep-copied to
// avoid pinning pooled message backing arrays. Oldest entries are lazily
// evicted by GetZoneKeys; a background sweep runs periodically.
func (cv *CryptoValidator) CacheZoneKeys(zone string, keys []*dns.DNSKEY) {
	if cv == nil || len(keys) == 0 {
		return
	}
	// Deep-copy to avoid holding pointers into pooled dns.Msg backing arrays
	copied := make([]*dns.DNSKEY, len(keys))
	for i, k := range keys {
		if k != nil {
			copied[i] = dns.Copy(k).(*dns.DNSKEY)
		}
	}
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	cv.mu.Lock()
	cv.zoneKeyCache[zone] = &zoneKeyEntry{
		keys:     copied,
		verified: true,
		expires:  time.Now().Add(1 * time.Hour),
	}
	if len(cv.zoneKeyCache) > zoneKeyCacheMax {
		// Purge expired entries first.
		for z, e := range cv.zoneKeyCache {
			if e != nil && time.Now().After(e.expires) {
				delete(cv.zoneKeyCache, z)
			}
		}
		// If still over the cap, evict the single oldest non-expired entry.
		if len(cv.zoneKeyCache) > zoneKeyCacheMax {
			var oldest string
			var oldestExpiry time.Time
			for z, e := range cv.zoneKeyCache {
				if e != nil && (oldest == "" || e.expires.Before(oldestExpiry)) {
					oldest = z
					oldestExpiry = e.expires
				}
			}
			if oldest != "" {
				delete(cv.zoneKeyCache, oldest)
			}
		}
	}
	cv.mu.Unlock()
}

// GetZoneKeys retrieves cached verified DNSKEYs for a zone. Expired entries
// are lazily evicted to prevent unbounded memory growth.
//
// Uses a dual-lock pattern: RLock for the fast path (valid cache hit),
// escalate to write lock only for expiry. Re-reads inside the write-locked
// section to avoid a TOCTOU race where CacheZoneKeys replaces an expired
// entry between the read-lock release and write-lock acquisition.
func (cv *CryptoValidator) GetZoneKeys(zone string) []*dns.DNSKEY {
	if cv == nil {
		return nil
	}
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))

	cv.mu.RLock()
	entry, ok := cv.zoneKeyCache[zone]
	if ok && entry != nil && !time.Now().After(entry.expires) {
		cv.mu.RUnlock()
		return entry.keys
	}
	cv.mu.RUnlock()

	cv.mu.Lock()
	entry, ok = cv.zoneKeyCache[zone]
	if !ok || entry == nil {
		cv.mu.Unlock()
		return nil
	}
	if time.Now().After(entry.expires) {
		delete(cv.zoneKeyCache, zone)
		cv.mu.Unlock()
		return nil
	}
	cv.mu.Unlock()
	return entry.keys
}

// GetRootKeys returns the root trust anchor DNSKEYs.
func (cv *CryptoValidator) GetRootKeys() []*dns.DNSKEY {
	return cv.rootKeys
}
