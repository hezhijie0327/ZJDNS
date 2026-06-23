package resolver

import (
	"context"
	"strings"

	"github.com/miekg/dns"

	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/security"
)

// dnssecChain tracks the cryptographic trust chain state during recursive
// resolution. At each delegation level, verified parent DNSKEYs and child DS
// records are used to authenticate the child zone's DNSKEYs.
type dnssecChain struct {
	parentDNSKEYs   []*dns.DNSKEY
	childDS         []*dns.DS
	zoneDNSKEYs     []*dns.DNSKEY
	lastEDECode     uint16 // EDE code for the most recent validation failure
	zoneCutDetected bool   // set when answer RRSIGs are signed by a child zone's keys
}

func (rr *Recursive) validateWithDNSSEC(response *dns.Msg, currentDomain string, chain *dnssecChain) bool {
	crypto := rr.resolver.validator.Crypto
	// Extract DNSKEY records from the response
	dnskeyRecords := security.FindDNSKEYs(response.Answer)
	dnskeyRecords = append(dnskeyRecords, security.FindDNSKEYs(response.Extra)...)

	// If the response came from a zone with known DNSKEYs, verify the answer
	if len(chain.zoneDNSKEYs) > 0 && len(response.Answer) > 0 {
		validated, _ := crypto.ValidateResponse(response, currentDomain, chain.zoneDNSKEYs)
		if validated {
			return true
		}
	}

	// Verify newly discovered DNSKEY records using parent DS or self-signature
	if len(dnskeyRecords) > 0 {
		allSigs := security.CollectRRSIGs(response.Answer, response.Ns, response.Extra)
		dnskeyRRSIGs := security.FindRRSIGs(allSigs, dns.Fqdn(currentDomain), dns.TypeDNSKEY)

		// Verify using parent DS if available (delegation point)
		if len(chain.childDS) > 0 {
			if matchedKey, err := crypto.VerifyDelegationDS(chain.childDS, dnskeyRecords); err == nil && matchedKey != nil {
				chain.zoneDNSKEYs = dnskeyRecords
				crypto.CacheZoneKeys(currentDomain, dnskeyRecords)
				log.Debugf("SECURITY: verified zone DNSKEY for %s via DS match", currentDomain)
				return true
			}
		}

		// Verify using self-signature (root zone only -- embedded trust anchors
		// provide the root of trust; self-signed keys from any other zone are
		// not trustworthy without a DS chain from a verified parent).
		if currentDomain == "." {
			if err := crypto.SelfVerifyDNSKEY(dnskeyRecords, dnskeyRRSIGs); err == nil {
				chain.zoneDNSKEYs = dnskeyRecords
				crypto.CacheZoneKeys(currentDomain, dnskeyRecords)

				// Now verify the answer with the newly verified keys
				if len(response.Answer) > 0 {
					validated, _ := crypto.ValidateResponse(response, currentDomain, dnskeyRecords)
					return validated
				}
				return true
			}
		}
	}

	return false
}
func (rr *Recursive) updateDNSSECChain(ctx context.Context, response *dns.Msg, currentDomain, childZone string, nameservers []string, chain *dnssecChain) {
	crypto := rr.resolver.validator.Crypto

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
		rr.ensureZoneDNSKEYs(ctx, nameservers, currentDomain, chain)
		verifiedDS := rr.verifyDelegationDSRRSIG(response, childZone, chain, dsRecords)
		chain.childDS = verifiedDS
		if len(verifiedDS) > 0 {
			log.Debugf("SECURITY: verified %d DS record(s) for delegation to %s", len(verifiedDS), childZone)
		} else {
			log.Debugf("SECURITY: DS records for %s could not be verified (RRSIG check failed)", childZone)
		}
	} else {
		chain.childDS = nil // Insecure delegation (no DS in parent)
	}

	// The current zone's DNSKEYs become parent DNSKEYs for the child
	if len(chain.zoneDNSKEYs) > 0 {
		chain.parentDNSKEYs = chain.zoneDNSKEYs
	}

	// Check for cached DNSKEYs for the child zone
	cachedKeys := crypto.GetZoneKeys(childZone)
	if len(cachedKeys) > 0 {
		chain.zoneDNSKEYs = cachedKeys
	} else {
		chain.zoneDNSKEYs = nil
	}
}
func (rr *Recursive) ensureZoneDNSKEYs(ctx context.Context, nameservers []string, zone string, chain *dnssecChain) {
	if len(chain.zoneDNSKEYs) > 0 {
		return // Already have verified DNSKEYs for this zone
	}

	crypto := rr.resolver.validator.Crypto

	// Check cache first
	if cached := crypto.GetZoneKeys(zone); len(cached) > 0 {
		chain.zoneDNSKEYs = cached
		return
	}

	if len(nameservers) == 0 {
		log.Debugf("SECURITY: no nameservers available to query DNSKEY for %s", zone)
		return
	}

	// Query the zone's authoritative nameservers for DNSKEY records
	dnskeyQuestion := dns.Question{Name: dns.Fqdn(zone), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	dnskeyResp, err := rr.queryNameserversConcurrent(ctx, nameservers, dnskeyQuestion, nil, false)
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
	dnskeyRRSIGs := security.FindRRSIGs(allSigs, dns.Fqdn(zone), dns.TypeDNSKEY)

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
	if zone == "." {
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
func (rr *Recursive) verifyDelegationDSRRSIG(response *dns.Msg, childZone string, chain *dnssecChain, dsRecords []*dns.DS) []*dns.DS {
	crypto := rr.resolver.validator.Crypto
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
	dsRRSIGs := security.FindRRSIGs(allSigs, dns.Fqdn(childZone), dns.TypeDS)
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
func (rr *Recursive) finalizeDNSSEC(ctx context.Context, response *dns.Msg, nameservers []string, question dns.Question, currentDomain string, ecs *edns.ECSOption, forceTCP bool, chain *dnssecChain) bool {
	crypto := rr.resolver.validator.Crypto
	if len(response.Answer) == 0 {
		return false
	}

	// If we already have verified DNSKEYs for this zone, verify directly
	if len(chain.zoneDNSKEYs) > 0 {
		validated, err := crypto.ValidateResponse(response, currentDomain, chain.zoneDNSKEYs)
		if err != nil {
			log.Debugf("SECURITY: answer RRSIG verification failed for %s: %v", question.Name, err)
			chain.lastEDECode = edns.EDECodeDNSSECBogus
			// Before treating as bogus, check if the RRSIG signer is from a
			// different zone (zone cut). If so, the answer was signed by child
			// zone keys and we need to follow the delegation instead of
			// returning SERVFAIL.
			if rr.isZoneCut(response, currentDomain) {
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
	dnskeyQuestion := dns.Question{Name: dns.Fqdn(currentDomain), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	dnskeyResp, err := rr.queryNameserversConcurrent(ctx, nameservers, dnskeyQuestion, ecs, forceTCP)
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
	dnskeyRRSIGs := security.FindRRSIGs(allSigs, dns.Fqdn(currentDomain), dns.TypeDNSKEY)

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
	} else {
		// No DS in parent — insecure delegation. Self-verify for root zone.
		if currentDomain == "." {
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

	validated, err := crypto.ValidateResponse(response, currentDomain, dnskeyRecords)
	if err != nil {
		log.Debugf("SECURITY: answer RRSIG verification failed for %s: %v", question.Name, err)
		chain.lastEDECode = edns.EDECodeDNSSECBogus
		// Check for zone cut: RRSIG signer from child zone, not current zone.
		if rr.isZoneCut(response, currentDomain) {
			log.Debugf("SECURITY: zone cut detected for %s — RRSIG signer differs from %s", question.Name, currentDomain)
			chain.zoneCutDetected = true
			return false
		}
	} else if !validated {
		chain.lastEDECode = edns.EDECodeRRSIGsMissing
	}
	return validated
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
	for _, rr := range answer {
		if rr == nil {
			continue
		}
		h := rr.Header()
		sigs := security.FindRRSIGs(allSigs, h.Name, h.Rrtype)
		if len(sigs) == 0 {
			// No RRSIG — record belongs to this zone (unsigned).
			result = append(result, rr)
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
			result = append(result, rr)
		} else {
			log.Debugf("SECURITY: stripping cross-zone record %s/%s from %s answer", h.Name, dns.TypeToString[h.Rrtype], zone)
		}
	}
	return result
}
