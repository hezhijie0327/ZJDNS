package resolver

import (
	"context"
	"errors"
	"fmt"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pending"
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
}

// errDNSKEYSelfSign is returned by verifyDNSKEYWithDS when the child zone's
// DNSKEY RRset is not signed by the DS-matched key (RFC 4035 §5.2).  A DS
// digest match proves only ONE key belongs to the zone; without the matched
// key's signature over the entire RRset, an attacker who can inject the
// DNSKEY response could append a rogue key and validate forged answers with
// it (CryptoValidator.IsResponseValid accepts any key in the slice).
var errDNSKEYSelfSign = errors.New("DNSKEY RRset not signed by DS-matched key")

// verifyDNSKEYWithDS authenticates a child zone's DNSKEY RRset against the
// parent's DS records: at least one key must match a DS digest (RFC 4035
// §5.2 step 1), AND that matched key must sign the entire RRset (step 2).
// Verifying with the matched key specifically — not any key in the set —
// is what binds the RRset to the DS: an on-path attacker who appends their
// own key can self-sign the modified set, but cannot forge the matched key's
// signature.  Returns the matched key on success; the VerifyDelegationDS
// error (ErrNoDS / ErrDSMismatch / ErrUnsupportedDigest / ErrNoZoneKeyBit)
// is preserved for EDE classification, and errDNSKEYSelfSign is returned
// when no RRSIG from the matched key covers the RRset.
func verifyDNSKEYWithDS(crypto *dnssec.CryptoValidator, childDS []*dns.DS, dnskeyRecords []*dns.DNSKEY, dnskeyRRSIGs []*dns.RRSIG) (*dns.DNSKEY, error) {
	matchedKey, err := crypto.VerifyDelegationDS(childDS, dnskeyRecords)
	if err != nil || matchedKey == nil {
		return nil, err
	}
	rrset := make([]dns.RR, len(dnskeyRecords))
	for i, k := range dnskeyRecords {
		rrset[i] = k
	}
	for _, rrsig := range dnskeyRRSIGs {
		if rrsig.KeyTag != matchedKey.KeyTag() {
			continue
		}
		if err := crypto.VerifyRRset(rrset, rrsig, matchedKey); err == nil {
			return matchedKey, nil
		}
	}
	return nil, fmt.Errorf("%w: key_tag=%d", errDNSKEYSelfSign, matchedKey.KeyTag())
}

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
		validated, valErr := crypto.IsResponseValid(response, currentDomain, chain.zoneDNSKEYs)
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

func (r *Recursive) updateDNSSECChain(ctx context.Context, response *dns.Msg, currentDomain, childZone string, nameservers []string, chain *dnssecChain) {
	crypto := r.resolver.validator.Crypto

	// Extract DS records from the Authority section. The DS RRset MUST be
	// cryptographically signed by the parent zone's DNSKEY. Without this
	// verification, an on-path attacker can inject forged DS records and
	// completely bypass the DNSSEC chain of trust.
	// Look for DS records in both Authority and Answer sections.
	// When the same server hosts both parent and child zones, DS
	// records may appear in the Answer section instead of Authority.
	dsRecords := dnssec.FindDS(response.Ns)
	dsRecords = append(dsRecords, dnssec.FindDS(response.Answer)...)
	switch {
	case len(dsRecords) > 0:
		// Ensure we have verified DNSKEYs for the current (parent) zone.
		// Delegation responses don't carry DNSKEY records — query explicitly.
		r.ensureZoneDNSKEYs(ctx, nameservers, currentDomain, chain)
		verifiedDS := r.verifyDelegationDSRRSIG(response, childZone, chain, dsRecords)
		chain.childDS = verifiedDS
		chain.dsPresentButUnverified = false
		if len(verifiedDS) > 0 {
			log.Debugf("SECURITY: verified %d DS record(s) for delegation to %s", len(verifiedDS), childZone)
		} else {
			chain.dsPresentButUnverified = true
			log.Debugf("SECURITY: DS records for %s could not be verified (RRSIG check failed)", childZone)
		}
	default:
		// No DS records in the delegation response. A missing DS must be
		// proven by an authenticated NSEC/NSEC3 denial when the parent zone
		// is signed — otherwise an on-path attacker could strip the DS
		// RRset and downgrade a signed delegation to insecure (RFC 4035
		// §5.2). Unverifiable delegations are treated as bogus, never as
		// insecure. When the parent has no verifiable DNSKEYs (a genuinely
		// unsigned parent), the delegation is insecure.
		if !r.resolver.DNSSECEnforce {
			// Enforcement off: the no-DS denial only gates bogus
			// classification, which enforcement never reaches — a missing
			// DS means insecure outright.  Skipping the DS + DNSKEY
			// verification saves 1-2 RTT per unsigned delegation level
			// (most CN domains — qq.com, baidu.com, tencent-cloud.net —
			// are unsigned).  Signed domains (DS present) keep the full
			// chain build above.
			chain.childDS = nil
			chain.dsPresentButUnverified = false
			log.Debugf("SECURITY: no DS for %s — insecure delegation (no-DS verification skipped, enforce off)", childZone)
			break
		}
		noDS, dsRaced := r.verifyNoDSInParent(ctx, nameservers, childZone, currentDomain, chain)
		switch {
		case noDS:
			chain.childDS = nil
			chain.dsPresentButUnverified = false
			log.Debugf("SECURITY: authenticated no-DS denial for %s (insecure delegation)", childZone)
		case dsRaced:
			// The DS query raced the delegation: verifyNoDSInParent verified
			// the DS inline and recorded the outcome in the chain — a
			// verified DS is set in chain.childDS, a failed verification
			// left dsPresentButUnverified set, so the delegation stays
			// unverifiable, never downgraded to insecure.
			if chain.dsPresentButUnverified {
				log.Debugf("SECURITY: raced DS for %s could not be verified — delegation unverifiable", childZone)
			}
		case len(chain.zoneDNSKEYs) == 0:
			chain.childDS = nil
			chain.dsPresentButUnverified = false
			log.Debugf("SECURITY: parent zone without DNSKEYs — insecure delegation for %s", childZone)
		default:
			chain.childDS = nil
			chain.dsPresentButUnverified = true
			log.Debugf("SECURITY: no authenticated denial for missing DS at %s — delegation unverifiable", childZone)
		}
	}

	// Check for cached DNSKEYs for the child zone
	cachedKeys := crypto.ZoneKeys(childZone)
	if len(cachedKeys) > 0 {
		chain.zoneDNSKEYs = cachedKeys
	} else {
		chain.zoneDNSKEYs = nil
	}
}

// verifyNoDSInParent confirms that a signed parent zone has no DS record at
// the delegation point by requiring an authenticated NSEC/NSEC3 denial from
// the parent's authoritative servers.  Returns (denialValid, dsRaced):
// denialValid is false when the denial cannot be proven (the delegation must
// then be treated as unverifiable, not insecure); dsRaced is true when the DS
// query found DS records — the delegation response simply raced the
// delegation, so the DS was verified inline against the parent's keys and
// chain.childDS / chain.dsPresentButUnverified were set accordingly.
func (r *Recursive) verifyNoDSInParent(ctx context.Context, nameservers []string, childZone, currentDomain string, chain *dnssecChain) (denialValid, dsRaced bool) {
	crypto := r.resolver.validator.Crypto
	if crypto == nil {
		return false, false
	}
	if len(chain.zoneDNSKEYs) == 0 {
		// The denial can only be verified against the parent zone's keys,
		// and the DS-present branch that normally loads them did not fire.
		r.ensureZoneDNSKEYs(ctx, nameservers, currentDomain, chain)
	}
	if len(chain.zoneDNSKEYs) == 0 {
		// Parent has no verifiable DNSKEYs — cannot authenticate a denial.
		return false, false
	}

	dsQuestion := Question{Name: dnsutil.Fqdn(childZone), Qtype: dns.TypeDS, Qclass: dns.ClassINET}
	resp, _, err := r.queryNameserversConcurrent(ctx, nameservers, dsQuestion, nil, false, currentDomain, r.resolver.validator.Poisonguard) // _ = verdict: poison already gated per-response in queryNameserversConcurrent
	if err != nil || resp == nil {
		log.Debugf("SECURITY: DS query for %s failed: %v", childZone, err)
		return false, false
	}
	defer pool.DefaultMessage.Put(resp)

	// A DS answer means the delegation response raced the delegation — e.g.
	// a same-server parent+child shortcut answered the referral without DS.
	// The caller has no response to verify, so verify it here against the
	// parent's keys and record it in the chain.
	dsRecords := dnssec.FindDS(resp.Answer)
	dsRecords = append(dsRecords, dnssec.FindDS(resp.Ns)...)
	if len(dsRecords) > 0 {
		if verified := r.verifyDelegationDSRRSIG(resp, childZone, chain, dsRecords); len(verified) > 0 {
			chain.childDS = verified
			chain.dsPresentButUnverified = false
			log.Debugf("SECURITY: verified %d DS record(s) for delegation to %s (raced)", len(verified), childZone)
		} else {
			chain.childDS = nil
			chain.dsPresentButUnverified = true
			log.Debugf("SECURITY: raced DS records for %s could not be verified — delegation unverifiable", childZone)
		}
		return false, true
	}

	validated, valErr := crypto.IsResponseValid(resp, childZone, chain.zoneDNSKEYs)
	if valErr != nil {
		log.Debugf("SECURITY: no-DS denial verification error for %s: %v", childZone, valErr)
	}
	return validated, false
}

func (r *Recursive) ensureZoneDNSKEYs(ctx context.Context, nameservers []string, zone string, chain *dnssecChain) {
	if len(chain.zoneDNSKEYs) > 0 {
		return // Already have verified DNSKEYs for this zone
	}

	crypto := r.resolver.validator.Crypto
	if crypto == nil {
		return
	}

	// Check cache first
	if cached := crypto.ZoneKeys(zone); len(cached) > 0 {
		chain.zoneDNSKEYs = cached
		return
	}

	if len(nameservers) == 0 {
		log.Debugf("SECURITY: no nameservers available to query DNSKEY for %s", zone)
		return
	}

	// Singleflight per zone: each walk fetches DNSKEYs for the zones it
	// crosses, and the zone-key cache (CacheZoneKeys) deduplicates across
	// walks once a fetch succeeds — but the cache only helps AFTER the first
	// fetch completes.  Without a flight, a cold-cache burst of N concurrent
	// walks each fires its own multi-NS DNSKEY query (N×len(nameservers)
	// parallel upstream queries, contexts, timers and pool buffers), which
	// amplified traffic bursts into multi-hundred-MB heap spikes (pprof
	// evidence, 2026-08).  ResultGroup gives wait-for-result semantics: one
	// leader fetches+verifies+caches; concurrent walkers receive the verified
	// keys without duplicating the fetch.
	r.dnskeyFlightOnce.Do(func() {
		r.dnskeyFlight = pending.NewResultGroup[string, []*dns.DNSKEY]()
	})
	// _ = error/leader: a follower whose ctx expired gets the zero value;
	// the len(keys) check below treats it as a miss.
	keys, _, _ := r.dnskeyFlight.Do(ctx, dnsutil.Canonical(dnsutil.Fqdn(zone)), func(ctx context.Context) ([]*dns.DNSKEY, error) {
		// A concurrent walk may have populated the zone-key cache while we
		// waited for leadership — re-check before fetching.
		if cached := crypto.ZoneKeys(zone); len(cached) > 0 {
			return cached, nil
		}
		r.fetchZoneDNSKEYs(ctx, nameservers, zone, chain)
		return chain.zoneDNSKEYs, nil
	})
	if len(keys) > 0 {
		chain.zoneDNSKEYs = keys
	}
}

// fetchZoneDNSKEYs queries the zone's authoritative nameservers for DNSKEY
// records, verifies them (DS match, offline KSK, root trust anchors) and
// caches the verified keys.
func (r *Recursive) fetchZoneDNSKEYs(ctx context.Context, nameservers []string, zone string, chain *dnssecChain) {
	crypto := r.resolver.validator.Crypto
	if crypto == nil {
		return
	}

	// Query the zone's authoritative nameservers for DNSKEY records
	dnskeyQuestion := Question{Name: dnsutil.Fqdn(zone), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	dnskeyResp, _, err := r.queryNameserversConcurrent(ctx, nameservers, dnskeyQuestion, nil, false, zone, r.resolver.validator.Poisonguard) // _ = verdict: poison already gated per-response in queryNameserversConcurrent
	if err != nil {
		log.Debugf("SECURITY: DNSKEY query failed for %s: %v", zone, err)
		return
	}
	defer pool.DefaultMessage.Put(dnskeyResp)

	dnskeyRecords := dnssec.FindDNSKEYs(dnskeyResp.Answer)
	if len(dnskeyRecords) == 0 {
		log.Debugf("SECURITY: no DNSKEY records found for %s", zone)
		return
	}

	allSigs := dnssec.CollectRRSIGs(dnskeyResp.Answer, dnskeyResp.Ns, dnskeyResp.Extra)
	dnskeyRRSIGs := dnssec.FindRRSIGs(allSigs, dnsutil.Fqdn(zone), dns.TypeDNSKEY)

	// Verify using parent DS if available (secure delegation).  The DS
	// match AND the matched key's signature over the whole RRset must
	// both hold (RFC 4035 §5.2) — see verifyDNSKEYWithDS.
	if len(chain.childDS) > 0 {
		if matchedKey, err := verifyDNSKEYWithDS(crypto, chain.childDS, dnskeyRecords, dnskeyRRSIGs); err == nil && matchedKey != nil {
			chain.zoneDNSKEYs = dnskeyRecords
			crypto.CacheZoneKeys(zone, dnskeyRecords)
			log.Debugf("SECURITY: verified zone DNSKEY for %s via DS match (key_tag=%d)", zone, matchedKey.KeyTag())
			return
		}
		// DS→DNSKEY mismatch may indicate an offline KSK (RFC 7344): the KSK
		// is referenced by the parent DS but not published in the DNSKEY set.
		// CDS/CDNSKEY records in the child zone carry the intended DS/key,
		// signed by the offline KSK. The digest match against the parent DS
		// (full SHA-256) is cryptographically equivalent to DS validation —
		// an attacker who can forge a matching digest already owns the keys.
		// The DNSKEY set is then bound to the matched digest: a key in the
		// set must produce the same digest (the CDS/CDNSKEY and the DNSKEY
		// are separate responses — the match authenticates the KSK, the
		// binding prevents an injected rogue key from riding along).
		//
		// DESIGN NOTE: verifyOfflineKSK (→ verifyViaCDS / verifyViaCDNSKEY)
		// is intentionally kept as a defense-in-depth measure for true offline
		// KSK deployments.  This is NOT dead code — do not remove.
		if matchedDS := r.verifyOfflineKSK(ctx, nameservers, zone, chain); matchedDS != nil {
			if _, err := crypto.VerifyDelegationDS([]*dns.DS{matchedDS}, dnskeyRecords); err != nil {
				log.Debugf("SECURITY: offline KSK matched for %s but DNSKEY set lacks the key: %v", zone, err)
				return
			}
			chain.zoneDNSKEYs = dnskeyRecords
			crypto.CacheZoneKeys(zone, dnskeyRecords)
			log.Debugf("SECURITY: verified zone DNSKEY for %s via offline KSK (CDS/CDNSKEY match)", zone)
			return
		}
		log.Debugf("SECURITY: DS→DNSKEY mismatch for %s", zone)
		return
	}

	// For root zone, verify via self-signature against embedded trust anchors.
	if zone == config.DNSRootZone {
		if err := crypto.SelfVerifyDNSKEY(dnskeyRecords, dnskeyRRSIGs); err != nil {
			log.Debugf("SECURITY: root DNSKEY self-verification failed: %v", err)
			return
		}
		// The self-signature proves the set is internally consistent; the
		// embedded trust anchors (RFC 7958) prove it is the real root.
		// Without this cross-check, a MITM of the root DNSKEY query could
		// inject a self-signed key set and forge the whole chain of trust.
		if !crypto.ContainsRootKey(dnskeyRecords) {
			log.Debugf("SECURITY: root DNSKEY set does not match embedded trust anchors")
			return
		}
		chain.zoneDNSKEYs = dnskeyRecords
		crypto.CacheZoneKeys(zone, dnskeyRecords)
		log.Debugf("SECURITY: self-verified root DNSKEY (matches trust anchors)")
		return
	}

	// Non-root zone without DS in parent — insecure delegation.
	log.Debugf("SECURITY: insecure delegation for %s — DNSKEYs not trusted (no DS in parent)", zone)
}

// verifyDelegationDSRRSIG cryptographically verifies the RRSIGs over DS records
// at a delegation point.
func (r *Recursive) verifyDelegationDSRRSIG(response *dns.Msg, childZone string, chain *dnssecChain, dsRecords []*dns.DS) []*dns.DS {
	crypto := r.resolver.validator.Crypto
	if crypto == nil {
		return nil
	}
	parentKeys := chain.zoneDNSKEYs
	if len(parentKeys) == 0 {
		// Never fall back to a previous delegation level's keys: verifying a
		// child DS against stale parent keys always fails and marks valid
		// delegations bogus. Fail closed when the parent's keys are unknown.
		log.Debugf("SECURITY: no parent DNSKEYs to verify DS RRSIG for %s", childZone)
		return nil
	}

	allSigs := dnssec.CollectRRSIGs(response.Ns, response.Extra, response.Answer)
	dsRRSIGs := dnssec.FindRRSIGs(allSigs, dnsutil.Fqdn(childZone), dns.TypeDS)
	if len(dsRRSIGs) == 0 {
		log.Debugf("SECURITY: no RRSIG found for DS records of %s", childZone)
		return nil
	}

	// Allocate RR slice for DS verification. This is a cold path
	// (only on delegation changes); pooling is not warranted.
	rrset := make([]dns.RR, len(dsRecords))
	for i, ds := range dsRecords {
		rrset[i] = ds
	}

	for _, rrsig := range dsRRSIGs {
		for _, key := range parentKeys {
			if key.KeyTag() != rrsig.KeyTag {
				continue
			}
			if err := crypto.VerifyRRset(rrset, rrsig, key); err == nil {
				log.Debugf("SECURITY: DS RRSIG verified for %s (key_tag=%d)", childZone, key.KeyTag())
				return dsRecords
			}
		}
	}

	log.Debugf("SECURITY: DS RRSIG verification failed for %s", childZone)
	return nil
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
func (r *Recursive) validateOrRetry(ctx context.Context, response *dns.Msg, nameservers []string, question Question, currentDomain string, ecs *edns.ECSOption, forceTCP bool, chain *dnssecChain, verifiedKeys []*dns.DNSKEY) bool {
	crypto := r.resolver.validator.Crypto

	validated, err := crypto.IsResponseValid(response, currentDomain, verifiedKeys)
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

// verifyOfflineKSK confirms an offline-KSK delegation (RFC 7344) via CDS or
// CDNSKEY: either record set matching the parent DS validates the delegation.
// CDS is tried first; CDNSKEY is the fallback (RFC 7344 §6).  Returns the
// matched digest record (as a DS) so the caller can bind the child zone's
// DNSKEY RRset to it — the CDS/CDNSKEY match alone authenticates the offline
// KSK; the DNSKEY set returned in a separate response must still be proven
// to contain that key.
//
// The match requires the FULL digest (not just key tag) to equal the parent DS
// — an attacker who can forge a SHA-256 preimage already owns the child zone's
// keys, so this is cryptographically equivalent to standard DS validation.
func (r *Recursive) verifyOfflineKSK(ctx context.Context, nameservers []string, zone string, chain *dnssecChain) *dns.DS {
	if ds := r.verifyViaCDS(ctx, nameservers, zone, chain); ds != nil {
		return ds
	}
	return r.verifyViaCDNSKEY(ctx, nameservers, zone, chain)
}

// verifyViaCDS confirms a secure delegation by querying the child zone's CDS
// records and checking that they match the parent DS (RFC 7344 §3.1).
func (r *Recursive) verifyViaCDS(ctx context.Context, nameservers []string, zone string, chain *dnssecChain) *dns.DS {
	cdsQ := Question{Name: dnsutil.Fqdn(zone), Qtype: dns.TypeCDS, Qclass: dns.ClassINET}
	cdsResp, _, err := r.queryNameserversConcurrent(ctx, nameservers, cdsQ, nil, false, zone, r.resolver.validator.Poisonguard) // _ = verdict: poison already gated per-response in queryNameserversConcurrent
	if err != nil || cdsResp == nil {
		log.Debugf("SECURITY: CDS query failed for %s: %v", zone, err)
		return nil
	}
	defer pool.DefaultMessage.Put(cdsResp)

	cdsRecords := dnssec.FindCDS(cdsResp.Answer)
	for _, ds := range chain.childDS {
		for _, cds := range cdsRecords {
			if cds.KeyTag == ds.KeyTag &&
				cds.Algorithm == ds.Algorithm &&
				cds.DigestType == ds.DigestType &&
				cds.Digest == ds.Digest {
				log.Debugf("SECURITY: CDS matches DS for %s (key_tag=%d)", zone, ds.KeyTag)
				// CDS shares the DS wire format (RFC 7344 §3.1) — the
				// embedded dns.DS is the binding record for the DNSKEY set.
				return &cds.DS
			}
		}
	}
	return nil
}

// verifyViaCDNSKEY confirms a secure delegation by querying the child zone's
// CDNSKEY records and computing their DS digests against the parent DS
// (RFC 7344 §3.2). The CDNSKEY RRSIG cannot be verified in the offline-KSK
// case (signed by the unpublished KSK), so the digest match against the parent
// DS is the effective authentication.
func (r *Recursive) verifyViaCDNSKEY(ctx context.Context, nameservers []string, zone string, chain *dnssecChain) *dns.DS {
	cdnskeyQ := Question{Name: dnsutil.Fqdn(zone), Qtype: dns.TypeCDNSKEY, Qclass: dns.ClassINET}
	cdnskeyResp, _, err := r.queryNameserversConcurrent(ctx, nameservers, cdnskeyQ, nil, false, zone, r.resolver.validator.Poisonguard) // _ = verdict: poison already gated per-response in queryNameserversConcurrent
	if err != nil || cdnskeyResp == nil {
		log.Debugf("SECURITY: CDNSKEY query failed for %s: %v", zone, err)
		return nil
	}
	defer pool.DefaultMessage.Put(cdnskeyResp)

	cdnskeyRecords := dnssec.FindCDNSKEY(cdnskeyResp.Answer)
	for _, ds := range chain.childDS {
		for _, cdnskey := range cdnskeyRecords {
			computed := cdnskey.ToDS(ds.DigestType)
			if computed == nil {
				continue
			}
			if computed.KeyTag == ds.KeyTag &&
				computed.Algorithm == ds.Algorithm &&
				computed.Digest == ds.Digest {
				log.Debugf("SECURITY: CDNSKEY→DS matches for %s (key_tag=%d)", zone, computed.KeyTag)
				return computed
			}
		}
	}
	return nil
}
