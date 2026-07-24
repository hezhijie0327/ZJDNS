package dnssec

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"zjdns/cache"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	zdnsutil "zjdns/internal/dnsutil"
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

// Common DNSSEC-related errors.
var (
	ErrNoRRSIG        = errors.New("no RRSIG found for rrset")
	ErrNoDNSKEY       = errors.New("no DNSKEY found for zone")
	ErrNoDS           = errors.New("no DS found for delegation")
	ErrDSMismatch     = errors.New("DS digest does not match DNSKEY")
	ErrBogusSignature = errors.New("bogus DNSSEC signature")
)

// NewCryptoValidator creates a CryptoValidator for DNSSEC validation. The
// cache store is used to persist verified zone DNSKEYs. Call LoadTrustAnchors
// to populate root trust anchors when recursive resolution is needed.
func NewCryptoValidator(store cache.Store) *CryptoValidator {
	return &CryptoValidator{cache: store}
}

// LoadTrustAnchors loads the IANA root trust anchors from file. Only needed
// for recursive resolution; upstream-only deployments can skip this call.
func (c *CryptoValidator) LoadTrustAnchors() {
	path := zdnsutil.ResolveDataFile(trustAnchorFileName, trustAnchorURL)
	if path == "" {
		log.Errorf("SECURITY: cannot determine trust anchor path — no root trust anchors loaded")
		return
	}
	keys, err := loadTrustAnchorsFromFile(path)
	if err != nil {
		log.Errorf("SECURITY: failed to load root trust anchors from %s: %v", path, err)
		return
	}
	c.rootKeys = keys
	log.Infof("SECURITY: loaded %d root trust anchor(s) from %s", len(keys), path)
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

	// Validate the RRset structure before verification (RFC 2181).
	if !dnsutil.IsRRset(rrset) {
		return fmt.Errorf("%w: not a valid RRset (type/name/class mismatch)", ErrBogusSignature)
	}

	// Check the RRSIG validity period manually (RFC 4034 §3.1.5).
	// miekg/dns RRSIG.Verify() also checks this, but the manual check
	// provides a more descriptive error message with the inception/expiration times.
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
		// For cross-zone records (signer not in any verified DNSKEY zone), skip
		// the RRset rather than rejecting it. The CNAME resolver will validate
		// them against their own zone's DNSKEYs.
		// SECURITY NOTE: in mixed RRsets (verified + cross-zone), cross-zone
		// records pass unverified when any other RRset validates successfully.
		// For cross-zone records, skip the RRset — the CNAME resolver will
		// validate them against their own zone's DNSKEYs.
		if !groupValidated {
			crossZone := true
			for _, sig := range sigs {
				fqSigner := dnsutil.Fqdn(sig.SignerName)
				for _, key := range verifiedDNSKEYs {
					fqKeyZone := dnsutil.Fqdn(key.Header().Name)
					if dnsutil.IsBelow(fqKeyZone, fqSigner) {
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
