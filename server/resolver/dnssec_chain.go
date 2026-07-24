package resolver

import (
	"context"
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
	dsRecords := dnssec.FindDS(response.Ns)
	dsRecords = append(dsRecords, dnssec.FindDS(response.Answer)...)
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

	// Verify using parent DS if available (secure delegation)
	if len(chain.childDS) > 0 {
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
	log.Debugf("SECURITY: insecure delegation for %s — DNSKEYs not trusted (no DS in parent)", zone)
}

// verifyDelegationDSRRSIG cryptographically verifies the RRSIGs over DS records
// at a delegation point.
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

	allSigs := dnssec.CollectRRSIGs(response.Ns, response.Extra, response.Answer)
	dsRRSIGs := dnssec.FindRRSIGs(allSigs, dnsutil.Fqdn(childZone), dns.TypeDS)
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
			chain.lastEDECode = dns.ExtendedErrorDNSBogus
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

	// Query the authoritative nameservers explicitly for DNSKEY + RRSIG
	dnskeyQuestion := Question{Name: dnsutil.Fqdn(currentDomain), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	dnskeyResp, _, err := r.queryNameserversConcurrent(ctx, nameservers, dnskeyQuestion, ecs, forceTCP, currentDomain, r.resolver.validator.Poisonguard)
	if err != nil {
		log.Debugf("SECURITY: DNSKEY query failed for %s: %v", currentDomain, err)
		chain.lastEDECode = dns.ExtendedErrorDNSKEYMissing
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
			chain.lastEDECode = dns.ExtendedErrorDNSKEYMissing
			return false
		}
	}

	if !keysVerified {
		chain.lastEDECode = dns.ExtendedErrorDNSKEYMissing
		return false
	}

	crypto.CacheZoneKeys(currentDomain, dnskeyRecords)
	chain.zoneDNSKEYs = dnskeyRecords

	validated, err := crypto.IsResponseValid(response, currentDomain, dnskeyRecords)
	if err != nil {
		log.Debugf("SECURITY: answer RRSIG verification failed for %s: %v", question.Name, err)
		chain.lastEDECode = dns.ExtendedErrorDNSBogus
		if r.isZoneCut(response, currentDomain) {
			log.Debugf("SECURITY: zone cut detected for %s — RRSIG signer differs from %s", question.Name, currentDomain)
			chain.zoneCutDetected = true
			return false
		}
	} else if !validated {
		chain.lastEDECode = dns.ExtendedErrorRRSIGsMissing
	}
	return validated
}

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
