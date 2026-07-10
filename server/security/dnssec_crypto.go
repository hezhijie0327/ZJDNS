package security

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"zjdns/cache"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
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
	now := uint32(log.NowUnix()) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
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
