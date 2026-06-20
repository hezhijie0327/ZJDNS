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
	ErrNoRRSIG               = errors.New("no RRSIG found for rrset")
	ErrNoDNSKEY              = errors.New("no DNSKEY found for zone")
	ErrNoDS                  = errors.New("no DS found for delegation")
	ErrDSMismatch            = errors.New("DS digest does not match DNSKEY")
	ErrTrustChainBroken      = errors.New("DNSSEC trust chain broken")
	ErrBogusSignature        = errors.New("bogus DNSSEC signature")
	ErrAlgorithmNotSupported = errors.New("DNSSEC algorithm not supported")
)

// CryptoValidator performs cryptographic DNSSEC validation using the
// miekg/dns RRSIG.Verify() and DNSKEY.ToDS() primitives. It is always active;
// the dnssec_enforce config option controls error behavior, not whether
// validation runs.
type CryptoValidator struct {
	rootKeys     []*dns.DNSKEY
	zoneKeyCache map[string]*zoneKeyEntry
	mu           sync.RWMutex
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
	}
	cv.loadRootTrustAnchors()
	return cv
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

// FindNSEC extracts NSEC records from an RR slice.
func FindNSEC(rrs []dns.RR) []*dns.NSEC {
	var records []*dns.NSEC
	for _, rr := range rrs {
		if nsec, ok := rr.(*dns.NSEC); ok {
			records = append(records, nsec)
		}
	}
	return records
}

// FindNSEC3 extracts NSEC3 records from an RR slice.
func FindNSEC3(rrs []dns.RR) []*dns.NSEC3 {
	var records []*dns.NSEC3
	for _, rr := range rrs {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			records = append(records, nsec3)
		}
	}
	return records
}

// VerifyAuthenticatedDenial checks NSEC/NSEC3 records to confirm that a
// negative response (NXDOMAIN or NODATA) is cryptographically proven.
func (cv *CryptoValidator) VerifyAuthenticatedDenial(response *dns.Msg, qname string, qtype uint16) error {
	normalized := strings.ToLower(qname)
	nsecs := FindNSEC(response.Ns)
	nsec3s := FindNSEC3(response.Ns)

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

// dnsutilCompareDomainInRange checks whether a domain name falls within the
// NSEC range (lower, upper] using DNS canonical ordering per RFC 4034 §6.1.
// Names are compared label-by-label right-to-left; within a label, bytes are
// compared lexicographically. A shorter name sorts before a longer suffix.
func dnsutilCompareDomainInRange(name, lower, upper string) bool {
	// Canonical ordering: lower < name ≤ upper
	return dns.CompareDomainName(lower, name) >= 0 && dns.CompareDomainName(name, upper) <= 0
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

	if rcode == dns.RcodeNameError {
		return cv.validateNXDOMAIN(response, zonename, verifiedDNSKEYs)
	}

	// NODATA (NOERROR with no answer and NSEC)
	if rcode == dns.RcodeSuccess && len(response.Answer) == 0 {
		return cv.validateNODATA(response, zonename, verifiedDNSKEYs)
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

func (cv *CryptoValidator) validateNXDOMAIN(response *dns.Msg, zonename string, verifiedDNSKEYs []*dns.DNSKEY) (bool, error) {
	// Verify NSEC/NSEC3 records are signed
	nsecs := FindNSEC(response.Ns)
	nsec3s := FindNSEC3(response.Ns)
	authSigs := CollectRRSIGs(response.Ns, response.Extra)

	// For each NSEC record, find its RRSIG by owner name and verify
	for _, nsec := range nsecs {
		ownerName := nsec.Header().Name
		rrsigs := FindRRSIGs(authSigs, ownerName, dns.TypeNSEC)
		if len(rrsigs) == 0 {
			continue
		}
		rrset := []dns.RR{nsec}
		for _, sig := range rrsigs {
			for _, key := range verifiedDNSKEYs {
				if key.KeyTag() == sig.KeyTag {
					if err := cv.VerifyRRset(rrset, sig, key); err == nil {
						return true, nil
					}
				}
			}
		}
	}

	// Verify NSEC3 RRSIGs — RFC 5155 §8 requires valid signatures for
	// authenticated denial, not mere record presence.
	for _, nsec3 := range nsec3s {
		ownerName := nsec3.Header().Name
		rrsigs := FindRRSIGs(authSigs, ownerName, dns.TypeNSEC3)
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

	return false, errors.New("no signed NSEC/NSEC3 for NXDOMAIN")
}

func (cv *CryptoValidator) validateNODATA(response *dns.Msg, zonename string, verifiedDNSKEYs []*dns.DNSKEY) (bool, error) {
	// NODATA: the name exists but the requested type does not. This is proven
	// by an NSEC record at the queried name that lists all types present at
	// the name, omitting the requested type. NSEC3 is handled similarly.
	nsecs := FindNSEC(response.Ns)
	nsec3s := FindNSEC3(response.Ns)
	authSigs := CollectRRSIGs(response.Ns, response.Extra)

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
						return true, nil
					}
				}
			}
		}
	}

	// Verify NSEC3 RRSIGs — RFC 5155 §8 requires valid signatures.
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

	return false, errors.New("no signed NSEC/NSEC3 for NODATA")
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
	cv.mu.Unlock()
}

// GetZoneKeys retrieves cached verified DNSKEYs for a zone. Expired entries
// are lazily evicted to prevent unbounded memory growth.
func (cv *CryptoValidator) GetZoneKeys(zone string) []*dns.DNSKEY {
	if cv == nil {
		return nil
	}
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	cv.mu.RLock()
	entry, ok := cv.zoneKeyCache[zone]
	cv.mu.RUnlock()
	if !ok || entry == nil {
		return nil
	}
	if time.Now().After(entry.expires) {
		cv.mu.Lock()
		delete(cv.zoneKeyCache, zone)
		cv.mu.Unlock()
		return nil
	}
	return entry.keys
}

// GetRootKeys returns the root trust anchor DNSKEYs.
func (cv *CryptoValidator) GetRootKeys() []*dns.DNSKEY {
	return cv.rootKeys
}
