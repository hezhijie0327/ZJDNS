package dnssec

import (
	"errors"
	"fmt"
	"time"
	"zjdns/cache"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	dnspool "codeberg.org/miekg/dns/pkg/pool"

	zdnsutil "zjdns/internal/dnsutil"
)

// CryptoValidator performs cryptographic DNSSEC validation using the
// miekg/dns RRSIG.Verify() and DNSKEY.ToDS() primitives. It is always active;
// the dnssec_enforce config option controls error behavior, not whether
// validation runs.
type CryptoValidator struct {
	rootKeys []*dns.DNSKEY
	cache    cache.Store

	// zoneKeyMemo caches the UNPACKED verified DNSKEYs per zone: the raw
	// cache hit path re-Unpacked + re-filtered the RR set on every call
	// (per delegation change, per walk).  Keys are shared read-only —
	// callers must not mutate them (verification only reads
	// flags/algorithm/key material).
	zoneKeyMemo *lrumap.Map[string, zoneKeyMemoEntry]
}

// zoneKeyMemoEntry is one memoised zone-key set with its expiry (cache
// entry TTL minus elapsed at memoise time).
type zoneKeyMemoEntry struct {
	keys   []*dns.DNSKEY
	expiry int64 // log.NowUnix()
}

type rrsetKey struct {
	name   string
	rrtype uint16
}

// Common DNSSEC-related errors.
var (
	ErrNoRRSIG              = errors.New("no RRSIG found for rrset")
	ErrMissingRRSIG         = errors.New("answer RRset has no RRSIG")
	ErrNoDNSKEY             = errors.New("no DNSKEY found for zone")
	ErrNoDS                 = errors.New("no DS found for delegation")
	ErrDSMismatch           = errors.New("DS digest does not match DNSKEY")
	ErrBogusSignature       = errors.New("bogus DNSSEC signature")
	ErrSignatureExpired     = errors.New("RRSIG signature has expired")
	ErrSignatureNotYet      = errors.New("RRSIG signature is not yet valid")
	ErrUnsupportedAlgorithm = errors.New("unsupported DNSKEY algorithm")
	ErrUnsupportedDigest    = errors.New("unsupported DS digest type")
	ErrNoZoneKeyBit         = errors.New("DNSKEY lacks the Zone Key flag")
	ErrMissingNSEC          = errors.New("no valid NSEC/NSEC3 denial-of-existence proof")
)

// NewCryptoValidator creates a CryptoValidator for DNSSEC validation. The
// cache store is used to persist verified zone DNSKEYs. Call LoadTrustAnchors
// to populate root trust anchors when recursive resolution is needed.
// sigBufPool is the shared buffer pool for RRSIG signature verification.
// miekg/dns defaults to a Noop pooler (a fresh 8KB buffer per call — 109MB
// cumulative allocations on a recursive server) unless SignOption.Pooler is
// provided; the real sync.Pool keeps allocations to pool misses only.
var sigBufPool = dnspool.New(8192)

func NewCryptoValidator(store cache.Store) *CryptoValidator {
	return &CryptoValidator{cache: store, zoneKeyMemo: lrumap.New[string, zoneKeyMemoEntry](512)}
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

// ContainsRootKey reports whether any KSK in dnskeys matches a loaded trust
// anchor. Required before trusting self-verified root DNSKEYs.
func (c *CryptoValidator) ContainsRootKey(dnskeys []*dns.DNSKEY) bool {
	for _, rk := range c.rootKeys {
		for _, k := range dnskeys {
			if k.Algorithm == rk.Algorithm &&
				k.KeyTag() == rk.KeyTag() &&
				k.PublicKey == rk.PublicKey {
				return true
			}
		}
	}
	return false
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

	// RFC 4034 §3.1.7: the RRSIG signer name must be the DNSKEY's owner name.
	// Explicit check so the invariant does not silently depend on the library.
	if !dns.EqualName(dnsutil.Fqdn(rrsig.SignerName), dnsutil.Fqdn(dnskey.Header().Name)) {
		return fmt.Errorf("%w: RRSIG signer %s does not match DNSKEY owner %s",
			ErrBogusSignature, rrsig.SignerName, dnskey.Header().Name)
	}

	// Check the RRSIG validity period manually (RFC 4034 §3.1.5: all
	// comparisons MUST use RFC 1982 serial-number arithmetic — plain < / >
	// misbehaves near the 2038/2106 32-bit wraparound).
	// miekg/dns RRSIG.Verify() also checks this, but the manual check
	// provides distinct sentinel errors for EDE 7/8 mapping.
	now := uint32(log.NowUnix()) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
	if serialLess(rrsig.Expiration, now) {
		return fmt.Errorf("%w: RRSIG expired at %s", ErrSignatureExpired, time.Unix(int64(rrsig.Expiration), 0).UTC())
	}
	if serialLess(now, rrsig.Inception) {
		return fmt.Errorf("%w: RRSIG not valid until %s", ErrSignatureNotYet, time.Unix(int64(rrsig.Inception), 0).UTC())
	}

	// Verify the cryptographic signature.  Legacy SHA-1 (RRSIG algorithms
	// 5/7, DS digest 1) is deliberately accepted for VERIFICATION: RFC 8624
	// §3.1 deprecates SHA-1 for signers, not validators — existing zones
	// signed before the transition must still validate.
	if err := rrsig.Verify(dnskey, rrset, &dns.SignOption{Pooler: sigBufPool}); err != nil {
		if errors.Is(err, dns.ErrAlg) {
			// EDE 1: the RRSIG uses an algorithm the library cannot verify
			// (e.g. DSA, GOST, or an unknown algorithm) — report precisely
			// instead of a generic bogus.
			return fmt.Errorf("%w: algorithm %d", ErrUnsupportedAlgorithm, rrsig.Algorithm)
		}
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

	var unsupportedDigest, noZoneKeyBit bool
	for _, ds := range dsRecords {
		for _, dnskey := range childDNSKEYs {
			// The SEP bit is a deployment convention (RFC 4034 §2.1.1), not a
			// validation requirement: RFC 4034/4035 do not require the key
			// referenced by a DS to have SEP set. Try every key; a digest
			// match is exact regardless of flags.
			computedDS := dnskey.ToDS(ds.DigestType)
			if computedDS == nil {
				// ToDS returns nil for digest types it cannot compute
				// (e.g. GOST) — remember for EDE 2 (Unsupported DS Digest
				// Type) if no DS matches after the loop.
				unsupportedDigest = true
				continue
			}
			if computedDS.KeyTag == ds.KeyTag &&
				computedDS.Algorithm == ds.Algorithm &&
				computedDS.DigestType == ds.DigestType &&
				computedDS.Digest == ds.Digest {
				// RFC 4034 §2.1.1: the Zone Key flag MUST be set on keys
				// used to sign zone data (EDE 11). Do not short-circuit —
				// during key rollover the DS set may still carry a DS for a
				// retired key whose Zone bit was cleared; keep scanning for
				// a valid zone-key match.
				if dnskey.Flags&dns.FlagZONE == 0 {
					noZoneKeyBit = true
					continue
				}
				log.Debugf("SECURITY: DS matched DNSKEY (key_tag=%d, alg=%s)", ds.KeyTag, dns.AlgorithmToString[ds.Algorithm])
				return dnskey, nil
			}
		}
	}

	// A digest matched a key that cannot sign zone data — the most precise
	// diagnosis; unsupported digest type next, generic mismatch last.
	if noZoneKeyBit {
		return nil, ErrNoZoneKeyBit
	}
	if unsupportedDigest {
		return nil, ErrUnsupportedDigest
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

	// The zone key self-signs the DNSKEY RRset. Try verifying with each key;
	// SEP is a convention, not a requirement (RFC 4034 §2.1.1).
	var verified bool
	for _, rrsig := range dnskeyRRSIGs {
		for _, ksk := range dnskeys {
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

	// RFC 6840 §4.1: the response is authenticated only if EVERY answer
	// RRset validates; a single valid RRset does not authenticate the rest.
	// First count signed RRsets: an unsigned RRset in an otherwise signed
	// response fails the whole response. RRSIG records are the signatures
	// themselves — they are never validated as an RRset.
	signedCount := 0
	for _, group := range groups {
		if len(group) > 0 && dns.RRToType(group[0]) != dns.TypeRRSIG &&
			len(FindRRSIGs(allRRSIGs, group[0].Header().Name, dns.RRToType(group[0]))) > 0 {
			signedCount++
		}
	}
	if signedCount == 0 {
		return false, ErrMissingRRSIG
	}

	// Key tags are memoised once per validation: miekg's KeyTag() computes
	// the RFC 4034 App. B digest on every call, and the sig×key loop below
	// re-derived it for every pair (s signatures × k keys per RRset group,
	// per level, per query — dominating the verify setup cost for
	// ECDSA/Ed25519 zones).
	keyTagIdx := make(map[uint16]int, len(verifiedDNSKEYs))
	for i, key := range verifiedDNSKEYs {
		keyTagIdx[key.KeyTag()] = i
	}

	var anyValidated bool
	for _, group := range groups {
		if len(group) == 0 {
			continue
		}
		header := group[0].Header()
		if dns.RRToType(group[0]) == dns.TypeRRSIG {
			continue // signature records are not validated as an RRset
		}
		sigs := FindRRSIGs(allRRSIGs, header.Name, dns.RRToType(group[0]))
		if len(sigs) == 0 {
			log.Debugf("SECURITY: unsigned RRset %s/%s in signed response", header.Name, dns.TypeToString[dns.RRToType(group[0])])
			return false, fmt.Errorf("%w: unsigned RRset %s/%s in signed response", ErrBogusSignature, header.Name, dns.TypeToString[dns.RRToType(group[0])])
		}

		var groupValidated bool
		var unsupportedAlgErr error
		for _, sig := range sigs {
			keyIdx, tagMatch := keyTagIdx[sig.KeyTag]
			if tagMatch {
				key := verifiedDNSKEYs[keyIdx]
				if err := c.VerifyRRset(group, sig, key); err == nil {
					anyValidated = true
					groupValidated = true
					log.Debugf("SECURITY: validated %s/%s with key_tag=%d", header.Name, dns.TypeToString[dns.RRToType(group[0])], sig.KeyTag)
					break
				} else if errors.Is(err, ErrUnsupportedAlgorithm) {
					// Remember ANY unsupported-algorithm failure — the
					// classification must not depend on RRSIG iteration
					// order when an RRset carries multiple signatures.
					unsupportedAlgErr = err
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
			// EDE 1: every attempted verification failed on an unsupported
			// algorithm — report that rather than the generic bogus.
			if unsupportedAlgErr != nil {
				return false, unsupportedAlgErr
			}
			return false, fmt.Errorf("%w: no matching DNSKEY for RRSIG over %s/%s (key tags in RRSIGs do not match verified zone keys)",
				ErrBogusSignature, header.Name, dns.TypeToString[dns.RRToType(group[0])])
		}
	}

	if !anyValidated {
		return false, fmt.Errorf("%w: no answer RRset could be cryptographically verified", ErrBogusSignature)
	}
	return true, nil
}

// serialLess reports whether a precedes b in RFC 1982 §2 serial-number
// arithmetic (a is before b when the forward difference b-a is less than
// 2^31, taking wraparound into account).
func serialLess(a, b uint32) bool {
	return (a < b && b-a < 1<<31) || (a > b && a-b > 1<<31)
}

func groupRRset(rrs []dns.RR) map[rrsetKey][]dns.RR {
	groups := make(map[rrsetKey][]dns.RR, len(rrs)/2)
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		h := rr.Header()
		// Canonicalise the owner: RFC 4343-legal mixed-case owner names
		// (0x20 encoding) would otherwise split one RRset into two groups,
		// both failing RRSIG verification (an RRset must be complete for
		// verification) → false "bogus" on case-preserving servers.
		key := rrsetKey{name: dnsutil.Canonical(h.Name), rrtype: dns.RRToType(rr)}
		groups[key] = append(groups[key], rr)
	}
	return groups
}
