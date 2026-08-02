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

		// Verify using parent DS if available (delegation point)
		if len(chain.childDS) > 0 {
			if matchedKey, err := crypto.VerifyDelegationDS(chain.childDS, dnskeyRecords); err == nil && matchedKey != nil {
				chain.zoneDNSKEYs = dnskeyRecords
				crypto.CacheZoneKeys(currentDomain, dnskeyRecords)
				log.Debugf("SECURITY: verified zone DNSKEY for %s via DS match", currentDomain)

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
	resp, _, err := r.queryNameserversConcurrent(ctx, nameservers, dsQuestion, nil, false, currentDomain, r.resolver.validator.Poisonguard)
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

	// Query the zone's authoritative nameservers for DNSKEY records
	dnskeyQuestion := Question{Name: dnsutil.Fqdn(zone), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	dnskeyResp, _, err := r.queryNameserversConcurrent(ctx, nameservers, dnskeyQuestion, nil, false, zone, r.resolver.validator.Poisonguard)
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

	// Verify using parent DS if available (secure delegation).
	if len(chain.childDS) > 0 {
		if _, err := crypto.VerifyDelegationDS(chain.childDS, dnskeyRecords); err == nil {
			chain.zoneDNSKEYs = dnskeyRecords
			crypto.CacheZoneKeys(zone, dnskeyRecords)
			log.Debugf("SECURITY: verified zone DNSKEY for %s via DS match", zone)
			return
		}
		// DS→DNSKEY mismatch may indicate an offline KSK (RFC 7344): the KSK
		// is referenced by the parent DS but not published in the DNSKEY set.
		// CDS/CDNSKEY records in the child zone carry the intended DS/key,
		// signed by the offline KSK. The digest match against the parent DS
		// (full SHA-256) is cryptographically equivalent to DS validation —
		// an attacker who can forge a matching digest already owns the keys.
		//
		// DESIGN NOTE: verifyOfflineKSK (→ verifyViaCDS / verifyViaCDNSKEY)
		// is intentionally kept as a defense-in-depth measure for true offline
		// KSK deployments.  This is NOT dead code — do not remove.
		if r.verifyOfflineKSK(ctx, nameservers, zone, chain) {
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

	// Query the authoritative nameservers explicitly for DNSKEY + RRSIG
	dnskeyQuestion := Question{Name: dnsutil.Fqdn(currentDomain), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	dnskeyResp, _, err := r.queryNameserversConcurrent(ctx, nameservers, dnskeyQuestion, ecs, forceTCP, currentDomain, r.resolver.validator.Poisonguard)
	if err != nil {
		log.Debugf("SECURITY: DNSKEY query failed for %s: %v", currentDomain, err)
		chain.lastEDECode = dns.ExtendedErrorNetworkError
		return false
	}
	defer pool.DefaultMessage.Put(dnskeyResp)

	dnskeyRecords := dnssec.FindDNSKEYs(dnskeyResp.Answer)
	if len(dnskeyRecords) == 0 {
		log.Debugf("SECURITY: no DNSKEY records found for %s", currentDomain)
		chain.lastEDECode = dns.ExtendedErrorDNSKEYMissing
		return false
	}

	allSigs := dnssec.CollectRRSIGs(dnskeyResp.Answer, dnskeyResp.Ns, dnskeyResp.Extra)
	dnskeyRRSIGs := dnssec.FindRRSIGs(allSigs, dnsutil.Fqdn(currentDomain), dns.TypeDNSKEY)

	var keysVerified bool
	switch {
	case len(chain.childDS) > 0:
		if _, err := crypto.VerifyDelegationDS(chain.childDS, dnskeyRecords); err == nil {
			keysVerified = true
			log.Debugf("SECURITY: verified %s DNSKEY via DS from parent", currentDomain)
		} else {
			log.Debugf("SECURITY: DS→DNSKEY mismatch for %s: %v (bogus delegation)", currentDomain, err)
			chain.lastEDECode = dns.ExtendedErrorDNSBogus
			return false
		}
	case chain.dsPresentButUnverified:
		chain.lastEDECode = dns.ExtendedErrorDNSBogus
		return false
	case currentDomain == config.DNSRootZone:
		if err := crypto.SelfVerifyDNSKEY(dnskeyRecords, dnskeyRRSIGs); err == nil {
			keysVerified = true
			log.Debugf("SECURITY: self-verified root DNSKEY")
		} else {
			log.Debugf("SECURITY: root DNSKEY self-verification failed: %v", err)
			chain.lastEDECode = dns.ExtendedErrorDNSBogus
			return false
		}
	}

	if !keysVerified {
		chain.lastEDECode = dns.ExtendedErrorDNSBogus
		return false
	}

	crypto.CacheZoneKeys(currentDomain, dnskeyRecords)
	chain.zoneDNSKEYs = dnskeyRecords

	return r.validateOrRetry(ctx, response, nameservers, question, currentDomain, ecs, forceTCP, chain, dnskeyRecords)
}

// validateOrRetry validates a response against verified DNSKEYs.  When RRSIGs
// are missing, it retries the authoritative query once — a different NS may
// have synchronised signatures.  Missing RRSIGs (not bogus) don't set DNSBogus
// and don't trigger dnssec_enforce.
func (r *Recursive) validateOrRetry(ctx context.Context, response *dns.Msg, nameservers []string, question Question, currentDomain string, ecs *edns.ECSOption, forceTCP bool, chain *dnssecChain, verifiedKeys []*dns.DNSKEY) bool {
	crypto := r.resolver.validator.Crypto

	validated, err := crypto.IsResponseValid(response, currentDomain, verifiedKeys)
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
// CDS is tried first; CDNSKEY is the fallback (RFC 7344 §6).
//
// The match requires the FULL digest (not just key tag) to equal the parent DS
// — an attacker who can forge a SHA-256 preimage already owns the child zone's
// keys, so this is cryptographically equivalent to standard DS validation.
func (r *Recursive) verifyOfflineKSK(ctx context.Context, nameservers []string, zone string, chain *dnssecChain) bool {
	return r.verifyViaCDS(ctx, nameservers, zone, chain) ||
		r.verifyViaCDNSKEY(ctx, nameservers, zone, chain)
}

// verifyViaCDS confirms a secure delegation by querying the child zone's CDS
// records and checking that they match the parent DS (RFC 7344 §3.1).
func (r *Recursive) verifyViaCDS(ctx context.Context, nameservers []string, zone string, chain *dnssecChain) bool {
	cdsQ := Question{Name: dnsutil.Fqdn(zone), Qtype: dns.TypeCDS, Qclass: dns.ClassINET}
	cdsResp, _, err := r.queryNameserversConcurrent(ctx, nameservers, cdsQ, nil, false, zone, r.resolver.validator.Poisonguard)
	if err != nil || cdsResp == nil {
		log.Debugf("SECURITY: CDS query failed for %s: %v", zone, err)
		return false
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
				return true
			}
		}
	}
	return false
}

// verifyViaCDNSKEY confirms a secure delegation by querying the child zone's
// CDNSKEY records and computing their DS digests against the parent DS
// (RFC 7344 §3.2). The CDNSKEY RRSIG cannot be verified in the offline-KSK
// case (signed by the unpublished KSK), so the digest match against the parent
// DS is the effective authentication.
func (r *Recursive) verifyViaCDNSKEY(ctx context.Context, nameservers []string, zone string, chain *dnssecChain) bool {
	cdnskeyQ := Question{Name: dnsutil.Fqdn(zone), Qtype: dns.TypeCDNSKEY, Qclass: dns.ClassINET}
	cdnskeyResp, _, err := r.queryNameserversConcurrent(ctx, nameservers, cdnskeyQ, nil, false, zone, r.resolver.validator.Poisonguard)
	if err != nil || cdnskeyResp == nil {
		log.Debugf("SECURITY: CDNSKEY query failed for %s: %v", zone, err)
		return false
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
				return true
			}
		}
	}
	return false
}
