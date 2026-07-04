package resolver

import (
	"context"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
	dnsutilv2 "codeberg.org/miekg/dns/dnsutil"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/security"
)

// Use config.DNSRootZone (".") instead of a local constant.

// dnssecChain tracks the cryptographic trust chain state during recursive
// resolution. At each delegation level, verified parent DNSKEYs and child DS
// records are used to authenticate the child zone's DNSKEYs.
type dnssecChain struct {
	parentDNSKEYs          []*dns.DNSKEY
	childDS                []*dns.DS
	zoneDNSKEYs            []*dns.DNSKEY
	lastEDECode            uint16 // EDE code for the most recent validation failure
	zoneCutDetected        bool   // set when answer RRSIGs are signed by a child zone's keys
	dsPresentButUnverified bool   // DS records found but RRSIG verification failed
}

func (r *Recursive) isValidWithDNSSEC(response *dns.Msg, currentDomain string, chain *dnssecChain) bool {
	crypto := r.resolver.validator.Crypto
	// Extract DNSKEY records from the response
	dnskeyRecords := security.FindDNSKEYs(response.Answer)
	dnskeyRecords = append(dnskeyRecords, security.FindDNSKEYs(response.Extra)...)

	// If the response came from a zone with known DNSKEYs, verify the answer
	if len(chain.zoneDNSKEYs) > 0 && len(response.Answer) > 0 {
		validated, _ := crypto.IsResponseValid(response, currentDomain, chain.zoneDNSKEYs)
		if validated {
			return true
		}
	}

	// Verify newly discovered DNSKEY records using parent DS or self-signature
	if len(dnskeyRecords) > 0 {
		allSigs := security.CollectRRSIGs(response.Answer, response.Ns, response.Extra)
		dnskeyRRSIGs := security.FindRRSIGs(allSigs, dnsutilv2.Fqdn(currentDomain), dns.TypeDNSKEY)

		// Verify using parent DS if available (delegation point)
		if len(chain.childDS) > 0 {
			if matchedKey, err := crypto.VerifyDelegationDS(chain.childDS, dnskeyRecords); err == nil && matchedKey != nil {
				chain.zoneDNSKEYs = dnskeyRecords
				crypto.CacheZoneKeys(currentDomain, dnskeyRecords)
				log.Debugf("SECURITY: verified zone DNSKEY for %s via DS match", currentDomain)

				// Now verify the answer with the newly verified keys
				if len(response.Answer) > 0 {
					validated, _ := crypto.IsResponseValid(response, currentDomain, dnskeyRecords)
					return validated
				}
				return true
			}
		}

		// Verify using self-signature (root zone only -- embedded trust anchors
		// provide the root of trust; self-signed keys from any other zone are
		// not trustworthy without a DS chain from a verified parent).
		if currentDomain == config.DNSRootZone {
			if err := crypto.SelfVerifyDNSKEY(dnskeyRecords, dnskeyRRSIGs); err == nil {
				chain.zoneDNSKEYs = dnskeyRecords
				crypto.CacheZoneKeys(currentDomain, dnskeyRecords)

				// Now verify the answer with the newly verified keys
				if len(response.Answer) > 0 {
					validated, _ := crypto.IsResponseValid(response, currentDomain, dnskeyRecords)
					return validated
				}
				return true
			}
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
	dsRecords := security.FindDS(response.Ns)
	dsRecords = append(dsRecords, security.FindDS(response.Answer)...)
	if len(dsRecords) > 0 {
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
	} else {
		chain.childDS = nil
		chain.dsPresentButUnverified = false // Insecure delegation (no DS in parent)
	}

	// The current zone's DNSKEYs become parent DNSKEYs for the child
	if len(chain.zoneDNSKEYs) > 0 {
		chain.parentDNSKEYs = chain.zoneDNSKEYs
	}

	// Check for cached DNSKEYs for the child zone
	cachedKeys := crypto.ZoneKeys(childZone)
	if len(cachedKeys) > 0 {
		chain.zoneDNSKEYs = cachedKeys
	} else {
		chain.zoneDNSKEYs = nil
	}
}

func (r *Recursive) ensureZoneDNSKEYs(ctx context.Context, nameservers []string, zone string, chain *dnssecChain) {
	if len(chain.zoneDNSKEYs) > 0 {
		return // Already have verified DNSKEYs for this zone
	}

	crypto := r.resolver.validator.Crypto

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
	dnskeyQuestion := Question{Name: dnsutilv2.Fqdn(zone), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	dnskeyResp, _, err := r.queryNameserversConcurrent(ctx, nameservers, dnskeyQuestion, nil, false, zone, r.resolver.validator.Hijack)
	if err != nil {
		log.Debugf("SECURITY: DNSKEY query failed for %s: %v", zone, err)
		return
	}
	defer pool.DefaultMessagePool.Put(dnskeyResp)

	dnskeyRecords := security.FindDNSKEYs(dnskeyResp.Answer)
	if len(dnskeyRecords) == 0 {
		log.Debugf("SECURITY: no DNSKEY records found for %s", zone)
		return
	}

	allSigs := security.CollectRRSIGs(dnskeyResp.Answer, dnskeyResp.Ns, dnskeyResp.Extra)
	dnskeyRRSIGs := security.FindRRSIGs(allSigs, dnsutilv2.Fqdn(zone), dns.TypeDNSKEY)

	// Verify using parent DS if available (secure delegation)
	if len(chain.childDS) > 0 {
		// childDS contains the DS for THIS zone (set in a previous
		// updateDNSSECChain call). Try matching DNSKEY → DS.
		if _, err := crypto.VerifyDelegationDS(chain.childDS, dnskeyRecords); err == nil {
			chain.zoneDNSKEYs = dnskeyRecords
			crypto.CacheZoneKeys(zone, dnskeyRecords)
			log.Debugf("SECURITY: verified zone DNSKEY for %s via DS match", zone)
			return
		}
		log.Debugf("SECURITY: DS→DNSKEY mismatch for %s: %v", zone, err)
		return
	}

	// For root zone, verify via self-signature against embedded trust anchors.
	// The root KSKs in trust anchors are the same keys returned in the root
	// DNSKEY query; SelfVerifyDNSKEY checks the RRSIG over the DNSKEY RRset
	// against the KSK present in the RRset.
	if zone == config.DNSRootZone {
		if err := crypto.SelfVerifyDNSKEY(dnskeyRecords, dnskeyRRSIGs); err == nil {
			chain.zoneDNSKEYs = dnskeyRecords
			crypto.CacheZoneKeys(zone, dnskeyRecords)
			log.Debugf("SECURITY: self-verified root DNSKEY")
			return
		}
		log.Debugf("SECURITY: root DNSKEY self-verification failed: %v", err)
		return
	}

	// Non-root zone without DS in parent — insecure delegation.
	// Self-signed DNSKEYs prove nothing; do not trust them for
	// verifying child DS RRSIGs.
	log.Debugf("SECURITY: insecure delegation for %s — DNSKEYs not trusted (no DS in parent)", zone)
}

// verifyDelegationDSRRSIG cryptographically verifies the RRSIGs over DS records
// at a delegation point. The 'chain' parameter carries the current delegation's
// DNSSEC state (zone DNSKEYs, parent DNSKEYs), while 'r' provides access to
// the CryptoValidator for signature verification.
func (r *Recursive) verifyDelegationDSRRSIG(response *dns.Msg, childZone string, chain *dnssecChain, dsRecords []*dns.DS) []*dns.DS {
	crypto := r.resolver.validator.Crypto
	parentKeys := chain.zoneDNSKEYs
	if len(parentKeys) == 0 {
		parentKeys = chain.parentDNSKEYs
	}
	if len(parentKeys) == 0 {
		log.Debugf("SECURITY: no parent DNSKEYs to verify DS RRSIG for %s", childZone)
		return nil
	}

	// Collect RRSIGs from all sections — DS RRSIGs may appear in
	// Answer section when the server is authoritative for the child zone.
	allSigs := security.CollectRRSIGs(response.Ns, response.Extra, response.Answer)
	dsRRSIGs := security.FindRRSIGs(allSigs, dnsutilv2.Fqdn(childZone), dns.TypeDS)
	if len(dsRRSIGs) == 0 {
		log.Debugf("SECURITY: no RRSIG found for DS records of %s", childZone)
		return nil
	}

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
	if len(response.Answer) == 0 {
		return false
	}

	// If we already have verified DNSKEYs for this zone, verify directly
	if len(chain.zoneDNSKEYs) > 0 {
		validated, err := crypto.IsResponseValid(response, currentDomain, chain.zoneDNSKEYs)
		if err != nil {
			log.Debugf("SECURITY: answer RRSIG verification failed for %s: %v", question.Name, err)
			chain.lastEDECode = edns.EDECodeDNSSECBogus
			// Before treating as bogus, check if the RRSIG signer is from a
			// different zone (zone cut). If so, the answer was signed by child
			// zone keys and we need to follow the delegation instead of
			// returning SERVFAIL.
			if r.isZoneCut(response, currentDomain) {
				log.Debugf("SECURITY: zone cut detected for %s — RRSIG signer differs from %s", question.Name, currentDomain)
				chain.zoneCutDetected = true
			}
			// Return false regardless — zone cut is signaled via zoneCutDetected flag
			return false
		}
		if !validated {
			chain.lastEDECode = edns.EDECodeRRSIGsMissing
		}
		return validated
	}

	// Query the authoritative nameservers explicitly for DNSKEY + RRSIG
	dnskeyQuestion := Question{Name: dnsutilv2.Fqdn(currentDomain), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	dnskeyResp, _, err := r.queryNameserversConcurrent(ctx, nameservers, dnskeyQuestion, ecs, forceTCP, currentDomain, r.resolver.validator.Hijack)
	if err != nil {
		log.Debugf("SECURITY: DNSKEY query failed for %s: %v", currentDomain, err)
		// DNSKEY query failure means the zone's DNSKEY records cannot be
		// retrieved, which is a DNSSEC-specific issue, not a generic network error.
		chain.lastEDECode = edns.EDECodeDNSKEYMissing
		return false
	}
	defer pool.DefaultMessagePool.Put(dnskeyResp)

	dnskeyRecords := security.FindDNSKEYs(dnskeyResp.Answer)
	if len(dnskeyRecords) == 0 {
		log.Debugf("SECURITY: no DNSKEY records found for %s", currentDomain)
		chain.lastEDECode = edns.EDECodeDNSKEYMissing
		return false
	}

	allSigs := security.CollectRRSIGs(dnskeyResp.Answer, dnskeyResp.Ns, dnskeyResp.Extra)
	dnskeyRRSIGs := security.FindRRSIGs(allSigs, dnsutilv2.Fqdn(currentDomain), dns.TypeDNSKEY)

	// Verify DNSKEY: try parent DS first (secure delegation), then
	// self-signature only when no DS exists (root zone or insecure delegation).
	var keysVerified bool
	if len(chain.childDS) > 0 {
		if _, err := crypto.VerifyDelegationDS(chain.childDS, dnskeyRecords); err == nil {
			keysVerified = true
			log.Debugf("SECURITY: verified %s DNSKEY via DS from parent", currentDomain)
		} else {
			// DS exists but doesn't match — this is a bogus delegation.
			log.Debugf("SECURITY: DS→DNSKEY mismatch for %s: %v (bogus delegation)", currentDomain, err)
			chain.lastEDECode = edns.EDECodeDNSSECBogus
			return false
		}
	} else if chain.dsPresentButUnverified {
		// DS records were found but RRSIG verification failed — bogus delegation
		// (not insecure). An attacker could inject unverifiable DS records to
		// bypass DNSSEC; treat as bogus.
		chain.lastEDECode = edns.EDECodeDNSSECBogus
		return false
	} else {
		// No DS in parent — insecure delegation. Self-verify for root zone.
		if currentDomain == config.DNSRootZone {
			if err := crypto.SelfVerifyDNSKEY(dnskeyRecords, dnskeyRRSIGs); err == nil {
				keysVerified = true
				log.Debugf("SECURITY: self-verified root DNSKEY")
			} else {
				log.Debugf("SECURITY: root DNSKEY self-verification failed: %v", err)
				chain.lastEDECode = edns.EDECodeDNSKEYMissing
				return false
			}
		}
	}

	if !keysVerified {
		chain.lastEDECode = edns.EDECodeDNSKEYMissing
		return false
	}

	// Cache the verified DNSKEY and verify the original answer's RRSIGs
	crypto.CacheZoneKeys(currentDomain, dnskeyRecords)
	chain.zoneDNSKEYs = dnskeyRecords

	validated, err := crypto.IsResponseValid(response, currentDomain, dnskeyRecords)
	if err != nil {
		log.Debugf("SECURITY: answer RRSIG verification failed for %s: %v", question.Name, err)
		chain.lastEDECode = edns.EDECodeDNSSECBogus
		// Check for zone cut: RRSIG signer from child zone, not current zone.
		if r.isZoneCut(response, currentDomain) {
			log.Debugf("SECURITY: zone cut detected for %s — RRSIG signer differs from %s", question.Name, currentDomain)
			chain.zoneCutDetected = true
			return false
		}
	} else if !validated {
		chain.lastEDECode = edns.EDECodeRRSIGsMissing
	}
	return validated
}

// recordDNSSECFailure stores the EDE code from the chain and returns a
// DNSSECError when enforcement is enabled and the zone is a secure delegation
// (has DS records in the parent). Returns nil when the delegation is insecure
// or enforcement is off. The validated parameter allows the caller to skip
// the check when validation already succeeded.
func (r *Recursive) recordDNSSECFailure(chain *dnssecChain, validated bool, msg string) error {
	if len(chain.childDS) == 0 || validated {
		return nil
	}
	r.lastDNSSECEDECode.Store(uint64(chain.lastEDECode))
	if !r.resolver.DNSSECEnforce {
		return nil
	}
	return &DNSSECError{EDECode: chain.lastEDECode, Message: msg}
}

// stripCrossZoneRecords removes answer records whose RRSIG signer name is
// from a different zone hierarchy than the given zone. These records need
// independent DNSSEC validation via CNAME chain following — they cannot be
// validated with the current zone's DNSKEYs and would otherwise cause a false
// bogus verdict (e.g. CDN A records for CNAME targets like aaplimg.com
// returned alongside CNAME records in the cdn-apple.com zone).
func stripCrossZoneRecords(answer, extra []dns.RR, zone string) []dns.RR {
	normalized := dnsutil.NormalizeDomain(zone)
	if normalized == "" {
		return answer
	}
	allSigs := security.CollectRRSIGs(answer, extra)

	result := make([]dns.RR, 0, len(answer))
	for _, r := range answer {
		if r == nil {
			continue
		}
		h := r.Header()
		sigs := security.FindRRSIGs(allSigs, h.Name, dns.RRToType(r))
		if len(sigs) == 0 {
			// No RRSIG — record belongs to this zone (unsigned).
			result = append(result, r)
			continue
		}
		inZone := false
		for _, sig := range sigs {
			signer := dnsutil.NormalizeDomain(sig.SignerName)
			if signer == normalized || strings.HasSuffix(signer, "."+normalized) {
				inZone = true
				break
			}
		}
		if inZone {
			result = append(result, r)
		} else {
			log.Debugf("SECURITY: stripping cross-zone record %s/%s from %s answer", h.Name, dns.TypeToString[dns.RRToType(r)], zone)
		}
	}
	return result
}

func (r *Recursive) getZoneCutSigner(response *dns.Msg, currentDomain string) string {
	if response == nil || len(response.Answer) == 0 {
		return ""
	}

	normalizedCurrent := dnsutil.NormalizeDomain(currentDomain)
	if normalizedCurrent == "" {
		return ""
	}

	rrsigs := security.CollectRRSIGs(response.Answer, response.Extra)
	for _, rrsig := range rrsigs {
		if rrsig == nil {
			continue
		}
		signerName := dnsutil.NormalizeDomain(rrsig.SignerName)
		if signerName != normalizedCurrent &&
			strings.HasSuffix(signerName, "."+normalizedCurrent) {
			return signerName
		}
	}

	return ""
}

func (r *Recursive) resolveZoneCut(ctx context.Context, response *dns.Msg, nameservers []string, question Question, currentDomain string, ecs *edns.ECSOption, forceTCP bool, chain *dnssecChain) (bool, error) {
	crypto := r.resolver.validator.Crypto

	// Extract the child zone name from the RRSIG signer
	childZone := r.getZoneCutSigner(response, currentDomain)
	if childZone == "" {
		return false, fmt.Errorf("could not determine child zone name from RRSIG signer")
	}

	// Ensure we have verified DNSKEYs for the parent zone
	if len(chain.zoneDNSKEYs) == 0 {
		r.ensureZoneDNSKEYs(ctx, nameservers, currentDomain, chain)
	}
	parentKeys := chain.zoneDNSKEYs
	if len(parentKeys) == 0 {
		parentKeys = chain.parentDNSKEYs
	}
	if len(parentKeys) == 0 {
		return false, fmt.Errorf("no parent DNSKEYs available to verify DS for %s", childZone)
	}

	// Query for the child zone's DS records from the parent zone.
	// These are used to verify the child zone's DNSKEYs.
	dsQuestion := Question{Name: dnsutilv2.Fqdn(childZone), Qtype: dns.TypeDS, Qclass: dns.ClassINET}
	dsResp, _, dsErr := r.queryNameserversConcurrent(ctx, nameservers, dsQuestion, ecs, forceTCP, currentDomain, r.resolver.validator.Hijack)
	if dsErr != nil {
		return false, fmt.Errorf("DS query for %s failed: %w", childZone, dsErr)
	}
	defer pool.DefaultMessagePool.Put(dsResp)

	dsRecords := security.FindDS(dsResp.Answer)
	dsRecords = append(dsRecords, security.FindDS(dsResp.Ns)...)
	if len(dsRecords) == 0 {
		// No DS at parent — the child zone is an insecure
		// delegation (unsigned). Clear the chain so the
		// bogus check does not fire on stale parent DS.
		chain.childDS = nil
		chain.dsPresentButUnverified = false
		return false, nil
	}

	// Verify DS RRSIGs against the parent zone's DNSKEYs
	allSigs := security.CollectRRSIGs(dsResp.Answer, dsResp.Ns, dsResp.Extra)
	dsRRSIGs := security.FindRRSIGs(allSigs, dnsutilv2.Fqdn(childZone), dns.TypeDS)
	if len(dsRRSIGs) == 0 {
		return false, fmt.Errorf("no RRSIG for DS records of %s", childZone)
	}

	rrset := make([]dns.RR, len(dsRecords))
	for i, ds := range dsRecords {
		rrset[i] = ds
	}

	var verifiedDS []*dns.DS
	for _, rrsig := range dsRRSIGs {
		for _, key := range parentKeys {
			if key.KeyTag() != rrsig.KeyTag {
				continue
			}
			if err := crypto.VerifyRRset(rrset, rrsig, key); err == nil {
				verifiedDS = dsRecords
				log.Debugf("SECURITY: zone cut — verified DS for %s (key_tag=%d)", childZone, key.KeyTag())
				break
			}
		}
		if len(verifiedDS) > 0 {
			break
		}
	}
	if len(verifiedDS) == 0 {
		return false, fmt.Errorf("DS RRSIG verification failed for %s", childZone)
	}

	// Update the trust chain with the verified DS records so the caller's
	// DNSSECEnforce check uses the correct child zone DS rather than stale
	// DS records from a prior delegation step.
	chain.childDS = verifiedDS

	// Query for the child zone's DNSKEY records
	dnskeyQuestion := Question{Name: dnsutilv2.Fqdn(childZone), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	dnskeyResp, _, dnskeyErr := r.queryNameserversConcurrent(ctx, nameservers, dnskeyQuestion, ecs, forceTCP, currentDomain, r.resolver.validator.Hijack)
	if dnskeyErr != nil {
		return false, fmt.Errorf("DNSKEY query for %s failed: %w", childZone, dnskeyErr)
	}
	defer pool.DefaultMessagePool.Put(dnskeyResp)

	dnskeyRecords := security.FindDNSKEYs(dnskeyResp.Answer)
	if len(dnskeyRecords) == 0 {
		return false, fmt.Errorf("no DNSKEY records found for %s", childZone)
	}

	// Verify child DNSKEYs against the verified DS records
	matchedKey, dsMatchErr := crypto.VerifyDelegationDS(verifiedDS, dnskeyRecords)
	if dsMatchErr != nil {
		log.Debugf("SECURITY: zone cut — DS→DNSKEY mismatch for %s: %v", childZone, dsMatchErr)
		chain.lastEDECode = edns.EDECodeDNSSECBogus
		return false, nil
	}
	log.Debugf("SECURITY: zone cut — verified DNSKEY for %s (key_tag=%d)", childZone, matchedKey.KeyTag())

	// Cache the verified child zone DNSKEYs
	crypto.CacheZoneKeys(childZone, dnskeyRecords)

	// Validate the original answer against the child zone's DNSKEYs.
	// Return (false, nil) on DNSSEC validation failure so the caller applies
	// the SERVFAIL check. The EDE code is set in chain.lastEDECode.
	validated, valErr := crypto.IsResponseValid(response, childZone, dnskeyRecords)
	if valErr != nil {
		log.Debugf("SECURITY: zone cut — answer RRSIG verification failed for %s: %v", question.Name, valErr)
		chain.lastEDECode = edns.EDECodeDNSSECBogus
		return false, nil
	}
	if !validated {
		chain.lastEDECode = edns.EDECodeRRSIGsMissing
		return false, nil
	}
	return true, nil
}

func (r *Recursive) isZoneCut(response *dns.Msg, currentDomain string) bool {
	return r.getZoneCutSigner(response, currentDomain) != ""
}
