package resolver

import (
	"context"
	"errors"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/resolver/dnssec"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// dnssecChain tracks the cryptographic trust chain state during recursive
// resolution. At each delegation level, verified parent DNSKEYs and child DS
// records are used to authenticate the child zone's DNSKEYs.
type dnssecChain struct {
	childDS                []*dns.DS
	zoneDNSKEYs            []*dns.DNSKEY
	lastEDECode            uint16 // EDE code for the most recent validation failure
	zoneCutDetected        bool   // set when answer RRSIGs are signed by a child zone's keys
	dsPresentButUnverified bool   // DS records found but RRSIG verification failed

	// verifyMemo caches the IsResponseValid outcome for the response of the
	// CURRENT delegation level: isValidWithDNSSEC runs at the level gate
	// (recursive.go) and isDNSSECValid re-ran the same full crypto
	// verification via processAnswerWithDNSSEC — twice the RRSA/ECDSA
	// verify cost per level on every signed-zone walk.  The response
	// pointer identifies the level's response (a new *dns.Msg per level);
	// the keys slice is compared by identity (chain.zoneDNSKEYs is not
	// mutated between the two call sites of one level).
	verifyMemo dnssecVerifyMemo
}

// dnssecVerifyMemo is the per-level verification cache (see dnssecChain).
type dnssecVerifyMemo struct {
	response *dns.Msg
	keys     []*dns.DNSKEY
	valid    bool
	err      error
}

// errDNSKEYSelfSign is returned by verifyDNSKEYWithDS when the child zone's
// DNSKEY RRset is not signed by the DS-matched key (RFC 4035 §5.2).  A DS
// digest match proves only ONE key belongs to the zone; without the matched
// key's signature over the entire RRset, an attacker who can inject the
// DNSKEY response could append a rogue key and validate forged answers with
// it (CryptoValidator.IsResponseValid accepts any key in the slice).
var errDNSKEYSelfSign = errors.New("DNSKEY RRset not signed by DS-matched key")

func (r *Recursive) isValidWithDNSSEC(response *dns.Msg, currentDomain string, chain *dnssecChain) bool {
	crypto := r.resolver.validator.Crypto
	if crypto == nil {
		return false
	}
	// Extract DNSKEY records from the response
	dnskeyRecords := dnssec.FindDNSKEYs(response.Answer)
	dnskeyRecords = append(dnskeyRecords, dnssec.FindDNSKEYs(response.Extra)...)

	// If the response came from a zone with known DNSKEYs, verify the answer
	if len(chain.zoneDNSKEYs) > 0 && len(response.Answer) > 0 {
		validated, valErr := r.verifyResponseOnce(chain, response, currentDomain, chain.zoneDNSKEYs)
		if validated {
			// Clear any EDE a previous delegation level left behind.
			chain.lastEDECode = 0
			return true
		}
		if valErr != nil {
			log.Debugf("SECURITY: DNSSEC validation error: %v", valErr)
		}
	}

	// Verify newly discovered DNSKEY records using parent DS or self-signature
	if len(dnskeyRecords) > 0 {
		allSigs := dnssec.CollectRRSIGs(response.Answer, response.Ns, response.Extra)
		dnskeyRRSIGs := dnssec.FindRRSIGs(allSigs, dnsutil.Fqdn(currentDomain), dns.TypeDNSKEY)

		// Verify using parent DS if available (delegation point).  The DS
		// match AND the matched key's signature over the whole RRset must
		// both hold (RFC 4035 §5.2) — see verifyDNSKEYWithDS.
		if len(chain.childDS) > 0 {
			if matchedKey, err := verifyDNSKEYWithDS(crypto, chain.childDS, dnskeyRecords, dnskeyRRSIGs); err == nil && matchedKey != nil {
				chain.zoneDNSKEYs = dnskeyRecords
				crypto.CacheZoneKeys(currentDomain, dnskeyRecords)
				log.Debugf("SECURITY: verified zone DNSKEY for %s via DS match (key_tag=%d)", currentDomain, matchedKey.KeyTag())

				// Now verify the answer with the newly verified keys
				if len(response.Answer) > 0 {
					validated, valErr := crypto.IsResponseValid(response, currentDomain, dnskeyRecords)
					if valErr != nil {
						log.Debugf("SECURITY: response validation error for %s: %v", currentDomain, valErr)
					}
					return validated
				}
				return true
			}
		}

		// Verify using self-signature (root zone only -- embedded trust anchors
		// provide the root of trust; self-signed keys from any other zone are
		// not trustworthy without a DS chain from a verified parent).
		if currentDomain == config.DNSRootZone {
			if err := crypto.SelfVerifyDNSKEY(dnskeyRecords, dnskeyRRSIGs); err != nil {
				log.Debugf("SECURITY: root DNSKEY self-verification failed: %v", err)
				return false
			}
			// The self-signature only proves internal consistency — a MITM
			// can trivially generate a self-signed key set. The embedded
			// trust anchors (RFC 7958) prove it is the real root; without
			// this cross-check the whole chain of trust can be forged.
			if !crypto.ContainsRootKey(dnskeyRecords) {
				log.Debugf("SECURITY: root DNSKEY set does not match embedded trust anchors")
				return false
			}
			chain.zoneDNSKEYs = dnskeyRecords
			crypto.CacheZoneKeys(currentDomain, dnskeyRecords)

			// Now verify the answer with the newly verified keys
			if len(response.Answer) > 0 {
				validated, valErr := crypto.IsResponseValid(response, currentDomain, dnskeyRecords)
				if valErr != nil {
					log.Debugf("SECURITY: response validation error for %s: %v", currentDomain, valErr)
				}
				return validated
			}
			return true
		}
	}

	return false
}

func (r *Recursive) isDNSSECValid(ctx context.Context, response *dns.Msg, nameservers []string, question Question, currentDomain string, ecs *edns.ECSOption, forceTCP bool, chain *dnssecChain) bool {
	crypto := r.resolver.validator.Crypto
	if crypto == nil {
		return false
	}
	if len(response.Answer) == 0 {
		return false
	}

	// If we already have verified DNSKEYs for this zone, verify directly
	if len(chain.zoneDNSKEYs) > 0 {
		return r.validateOrRetry(ctx, response, nameservers, question, currentDomain, ecs, forceTCP, chain, chain.zoneDNSKEYs)
	}

	if len(chain.childDS) == 0 {
		// Unsigned delegation (no DS at the cut): the zone has no verifiable
		// keys, so a DNSKEY fetch can only return empty — skip it, it would
		// cost one query per unsigned answer level for nothing.  The result
		// is the same: unvalidated, and (matching the caller) no EDE for
		// clean insecure delegations.
		return false
	}

	// Delegate to ensureZoneDNSKEYs — it fetches, verifies (DS / root
	// trust-anchor cross-check / insecure-delegation), and caches the keys.
	r.ensureZoneDNSKEYs(ctx, nameservers, currentDomain, chain)
	if len(chain.zoneDNSKEYs) == 0 {
		// A clean insecure delegation (updateDNSSECChain verified an
		// authenticated no-DS denial — an unsigned zone) is NOT a validation
		// failure: no EDE, and the response stays cacheable.  Only a
		// delegation that claimed DS records (or whose no-DS could not be
		// proven) is genuinely unverifiable and gets EDE 6 (DNSBogus) —
		// mirroring updateDNSSECChain's posture: unverifiable → bogus,
		// proven no-DS → insecure.
		if (len(chain.childDS) > 0 || chain.dsPresentButUnverified) && chain.lastEDECode == 0 {
			chain.lastEDECode = dns.ExtendedErrorDNSBogus
		}
		return false
	}

	return r.validateOrRetry(ctx, response, nameservers, question, currentDomain, ecs, forceTCP, chain, chain.zoneDNSKEYs)
}

// validateOrRetry validates a response against verified DNSKEYs.  When RRSIGs
// are missing, it retries the authoritative query once — a different NS may
// have synchronised signatures.  Missing RRSIGs (not bogus) don't set DNSBogus
// and don't trigger dnssec_enforce.
// verifyResponseOnce runs crypto.IsResponseValid with the per-level memo:
// the level gate (isValidWithDNSSEC) and processAnswerWithDNSSEC share one
// verification per response+keys pair instead of paying the full signature
// pass twice on every signed delegation level.
func (r *Recursive) verifyResponseOnce(chain *dnssecChain, response *dns.Msg, currentDomain string, keys []*dns.DNSKEY) (bool, error) {
	if m := chain.verifyMemo; m.response == response && sameKeySlice(m.keys, keys) {
		return m.valid, m.err
	}
	valid, err := r.resolver.validator.Crypto.IsResponseValid(response, currentDomain, keys)
	chain.verifyMemo = dnssecVerifyMemo{response: response, keys: keys, valid: valid, err: err}
	return valid, err
}

// sameKeySlice reports identity equality — the memo is only valid for the
// same underlying keys slice, never for equal-but-different sets.
func sameKeySlice(a, b []*dns.DNSKEY) bool {
	if len(a) == 0 || len(a) != len(b) {
		return len(a) == 0 && len(b) == 0
	}
	return &a[0] == &b[0]
}

func (r *Recursive) validateOrRetry(ctx context.Context, response *dns.Msg, nameservers []string, question Question, currentDomain string, ecs *edns.ECSOption, forceTCP bool, chain *dnssecChain, verifiedKeys []*dns.DNSKEY) bool {
	validated, err := r.verifyResponseOnce(chain, response, currentDomain, verifiedKeys)
	// A previous delegation level may have left a non-zero lastEDECode
	// (e.g. DNSBogus when the TLD's DNSKEYs were unreachable).  If THIS
	// level validates cleanly, the stale EDE must not surface to the
	// client — clear it before the success return below.
	if err == nil && validated {
		chain.lastEDECode = 0
	}
	if err != nil {
		log.Debugf("SECURITY: answer RRSIG verification failed for %s: %v", question.Name, err)

		if errors.Is(err, dnssec.ErrMissingRRSIG) {
			if r.tryRRSIGRetry(ctx, response, nameservers, question, currentDomain, ecs, forceTCP, verifiedKeys) {
				return true
			}
			chain.lastEDECode = dns.ExtendedErrorRRSIGsMissing
			return false
		}

		switch {
		case errors.Is(err, dnssec.ErrSignatureExpired):
			chain.lastEDECode = dns.ExtendedErrorSignatureExpired // EDE 7
		case errors.Is(err, dnssec.ErrSignatureNotYet):
			chain.lastEDECode = dns.ExtendedErrorSignatureNotYetValid // EDE 8
		case errors.Is(err, dnssec.ErrUnsupportedAlgorithm):
			chain.lastEDECode = dns.ExtendedErrorUnsupportedDNSKEYAlgorithm // EDE 1
		case errors.Is(err, dnssec.ErrMissingNSEC):
			chain.lastEDECode = dns.ExtendedErrorNSECMissing // EDE 12
		default:
			chain.lastEDECode = dns.ExtendedErrorDNSBogus // EDE 6
		}
		if r.isZoneCut(response, currentDomain) {
			log.Debugf("SECURITY: zone cut detected for %s — RRSIG signer differs from %s", question.Name, currentDomain)
			chain.zoneCutDetected = true
		}
		return false
	}
	if !validated {
		chain.lastEDECode = dns.ExtendedErrorRRSIGsMissing
	}
	return validated
}

// tryRRSIGRetry re-queries the authoritative nameservers and validates the
// response against the given verified keys.  Returns true if the retry
// succeeds with valid RRSIGs.
func (r *Recursive) tryRRSIGRetry(ctx context.Context, response *dns.Msg, nameservers []string, question Question, currentDomain string, ecs *edns.ECSOption, forceTCP bool, verifiedKeys []*dns.DNSKEY) bool {
	retryCtx, retryCancel := context.WithTimeout(ctx, config.DefaultDNSQueryTimeout)
	defer retryCancel()
	retryResp, _, retryErr := r.queryNameserversConcurrent(retryCtx, nameservers, question, ecs, forceTCP, currentDomain, r.resolver.validator.Poisonguard)
	if retryErr != nil || retryResp == nil {
		log.Debugf("SECURITY: RRSIG retry failed for %s", question.Name)
		return false
	}
	defer pool.DefaultMessage.Put(retryResp)

	retryValidated, retryValErr := r.resolver.validator.Crypto.IsResponseValid(retryResp, currentDomain, verifiedKeys)
	if retryValErr != nil || !retryValidated {
		log.Debugf("SECURITY: RRSIG retry failed for %s", question.Name)
		return false
	}

	log.Debugf("SECURITY: RRSIG retry succeeded for %s", question.Name)
	response.Answer = append([]dns.RR(nil), retryResp.Answer...)
	response.Ns = append([]dns.RR(nil), retryResp.Ns...)
	response.Extra = append([]dns.RR(nil), retryResp.Extra...)
	return true
}

func (r *Recursive) recordDNSSECFailure(chain *dnssecChain, validated bool, msg string) error {
	if len(chain.childDS) == 0 || validated {
		return nil
	}
	if !r.resolver.DNSSECEnforce {
		return nil
	}
	return &DNSSECError{EDECode: chain.lastEDECode, Message: msg}
}
