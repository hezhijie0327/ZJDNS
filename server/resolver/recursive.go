package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/security"
)

// DefaultRootServers is the IANA root server address list.
var DefaultRootServers = []string{
	"198.41.0.4:53", "[2001:503:ba3e::2:30]:53",
	"170.247.170.2:53", "[2801:1b8:10::b]:53",
	"192.33.4.12:53", "[2001:500:2::c]:53",
	"199.7.91.13:53", "[2001:500:2d::d]:53",
	"192.203.230.10:53", "[2001:500:a8::e]:53",
	"192.5.5.241:53", "[2001:500:2f::f]:53",
	"192.112.36.4:53", "[2001:500:12::d0d]:53",
	"198.97.190.53:53", "[2001:500:1::53]:53",
	"192.36.148.17:53", "[2001:7fe::53]:53",
	"192.58.128.30:53", "[2001:503:c27::2:30]:53",
	"193.0.14.129:53", "[2001:7fd::1]:53",
	"199.7.83.42:53", "[2001:500:9f::42]:53",
	"202.12.27.33:53", "[2001:dc3::35]:53",
}

// Recursive performs iterative DNS resolution by walking the root, TLD, and
// authoritative nameserver hierarchy. When DNSSEC validation is enabled, it
// builds a cryptographic chain of trust at each delegation step.
type Recursive struct {
	resolver          *Resolver
	lastDNSSECEDECode atomic.Uint64 // EDE code from the most recent DNSSEC validation failure
}

// DNSSECEDECode returns the last DNSSEC EDE code atomically.
func (r *Recursive) DNSSECEDECode() uint16 {
	return uint16(r.lastDNSSECEDECode.Load())
}

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

func (rr *Recursive) resolve(ctx context.Context, question dns.Question, ecs *edns.ECSOption, depth int, forceTCP bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	log.Debugf("RECURSION: depth=%d, querying %s (type=%s, tcp=%t)", depth, question.Name, dns.TypeToString[question.Qtype], forceTCP)
	if depth > MaxRecursionDep {
		log.Warnf("RECURSION: depth exceeded (depth=%d, max=%d) for %s", depth, MaxRecursionDep, question.Name)
		return nil, nil, nil, false, nil, "", false, fmt.Errorf("recursion depth exceeded: %d", depth)
	}

	qname := dns.Fqdn(question.Name)
	question.Name = qname
	nameservers := ShuffleSlice(DefaultRootServers)
	currentDomain := "."
	normalizedQname := dnsutil.NormalizeDomain(qname)
	var hijackDetected bool

	// Initialize DNSSEC trust chain with root trust anchors
	crypto := rr.resolver.validator.Crypto
	chain := &dnssecChain{}
	chain.parentDNSKEYs = crypto.GetRootKeys()

	if normalizedQname == "" {
		response, err := rr.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP)
		if err != nil {
			return nil, nil, nil, false, nil, "", false, fmt.Errorf("root domain query: %w", err)
		}

		if rr.resolver.validator.Hijack.IsEnabled() {
			if valid, reason := rr.resolver.validator.Hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				pool.DefaultMessagePool.Put(response)
				return rr.handleSuspiciousResponse(reason, forceTCP, ctx, question, ecs, depth)
			}
		}

		cryptoValidated := rr.validateWithDNSSEC(response, currentDomain, chain)
		validated := cryptoValidated
		ecsResponse := rr.resolver.edns.ParseFromDNS(response)
		answer, authority, additional := response.Answer, response.Ns, response.Extra
		pool.DefaultMessagePool.Put(response)
		return answer, authority, additional, validated, ecsResponse, config.RecursiveIndicator, false, nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, "", false, ctx.Err()
		default:
		}

		response, err := rr.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP)
		if err != nil {
			if !forceTCP && errors.Is(err, ErrHijackDetected) {
				return rr.resolve(ctx, question, ecs, depth, true)
			}
			return nil, nil, nil, false, nil, "", false, fmt.Errorf("query %s: %w", currentDomain, err)
		}

		if rr.resolver.validator.Hijack.IsEnabled() {
			if valid, reason := rr.resolver.validator.Hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				pool.DefaultMessagePool.Put(response)
				answer, authority, additional, validated, ecsResponse, server, hijackDetectedNow, err := rr.handleSuspiciousResponse(reason, forceTCP, ctx, question, ecs, depth)
				if hijackDetectedNow {
					hijackDetected = true
				}
				if !forceTCP && errors.Is(err, ErrHijackDetected) {
					return rr.resolve(ctx, question, ecs, depth, true)
				}
				return answer, authority, additional, validated, ecsResponse, server, hijackDetected, err
			}
		}

		// Cryptographic DNSSEC validation at this delegation level
		cryptoValidated := rr.validateWithDNSSEC(response, currentDomain, chain)
		ecsResponse := rr.resolver.edns.ParseFromDNS(response)

		validated := cryptoValidated

		if len(response.Answer) > 0 {
			validated = rr.finalizeDNSSEC(ctx, response, nameservers, question, currentDomain, ecs, forceTCP, chain)

			// If the answer RRSIGs are signed by a child zone's keys
			// (zone cut), process the response as a referral instead of
			// returning it as the final answer. This handles cases where
			// an authoritative server returns an answer directly from a
			// delegated subdomain instead of issuing a referral.
			if !validated && chain.zoneCutDetected {
				log.Debugf("SECURITY: zone cut — resolving DNSSEC chain for child zone of %s", question.Name)
				chain.zoneCutDetected = false
				// Build the DNSSEC chain for the child zone directly by querying
				// for DS and DNSKEY records, then validate the original answer
				// against the child zone's verified keys. This avoids relying on
				// the delegation-following path which requires NS+DS records in
				// specific response sections that may not be present.
				if cutValidated, cutErr := rr.resolveZoneCut(ctx, response, nameservers, question, currentDomain, ecs, forceTCP, chain); cutErr == nil {
					validated = cutValidated
					if rr.resolver.DNSSECEnforce && len(chain.childDS) > 0 && !validated {
						log.Debugf("SECURITY: DNSSEC validation failed for %s — zone cut child has DS but RRSIG verification failed", question.Name)
						rr.lastDNSSECEDECode.Store(uint64(chain.lastEDECode))
						pool.DefaultMessagePool.Put(response)
						return nil, nil, nil, false, ecsResponse, config.RecursiveIndicator, false,
							fmt.Errorf("DNSSEC validation failed: bogus zone cut delegation for %s", question.Name)
					}
				} else {
					log.Debugf("SECURITY: zone cut resolution failed for %s: %v", question.Name, cutErr)
					validated = false
				}
				answer, authority, additional := response.Answer, response.Ns, response.Extra
				pool.DefaultMessagePool.Put(response)
				return answer, authority, additional, validated, ecsResponse, config.RecursiveIndicator, false, nil
			} else {
				// When DNSSEC crypto is enabled and the zone has DS records in the
				// parent, a crypto verification failure means the answer is bogus.
				// Return SERVFAIL to match RFC 4035 behavior (e.g. dnssec-failed.org).
				if rr.resolver.DNSSECEnforce && len(chain.childDS) > 0 && !validated {
					log.Debugf("SECURITY: DNSSEC validation failed for %s — zone has DS but DNSKEY/RRSIG verification failed", question.Name)
					rr.lastDNSSECEDECode.Store(uint64(chain.lastEDECode))
					pool.DefaultMessagePool.Put(response)
					return nil, nil, nil, false, ecsResponse, config.RecursiveIndicator, false,
						fmt.Errorf("DNSSEC validation failed: bogus delegation for %s", question.Name)
				}
				answer, authority, additional := response.Answer, response.Ns, response.Extra
				pool.DefaultMessagePool.Put(response)
				return answer, authority, additional, validated, ecsResponse, config.RecursiveIndicator, false, nil
			}
		}

		// For NODATA/NXDOMAIN responses (no answer section), cryptographically
		// verify NSEC/NSEC3 records against the zone's verified DNSKEYs to
		// enable the AuthenticatedData flag when denial-of-existence is proven
		// (RFC 4035 §3.1.3). Genuine DNSSEC failures (bad RRSIGs on answer
		// records) are caught by the answer-path SERVFAIL check above.
		if len(response.Answer) == 0 {
			if len(chain.zoneDNSKEYs) == 0 {
				rr.ensureZoneDNSKEYs(ctx, nameservers, currentDomain, chain)
			}
			if len(chain.zoneDNSKEYs) > 0 {
				if nsecValidated, _ := rr.resolver.validator.Crypto.ValidateResponse(response, currentDomain, chain.zoneDNSKEYs); nsecValidated {
					validated = true
				}
			}
		}

		// Collect NS records from both Authority and Answer sections.
		// NS records appear in the Answer section when the queried
		// server is authoritative for the delegated zone (common when
		// the same server hosts both parent and child zones).
		var allRRSections []dns.RR
		allRRSections = append(allRRSections, response.Ns...)
		allRRSections = append(allRRSections, response.Answer...)

		bestMatch := ""
		var bestNSRecords []*dns.NS
		for _, rrec := range allRRSections {
			if ns, ok := rrec.(*dns.NS); ok {
				nsName := dnsutil.NormalizeDomain(rrec.Header().Name)
				isMatch := normalizedQname == nsName ||
					(nsName != "" && strings.HasSuffix(normalizedQname, "."+nsName))
				if isMatch && len(nsName) >= len(bestMatch) {
					if len(nsName) > len(bestMatch) {
						bestMatch = nsName
						bestNSRecords = []*dns.NS{ns}
					} else {
						bestNSRecords = append(bestNSRecords, ns)
					}
				}
			}
		}

		if len(bestNSRecords) == 0 {
			nsSlice, extraSlice := response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, config.RecursiveIndicator, false, nil
		}

		currentDomainNormalized := dnsutil.NormalizeDomain(currentDomain)
		if bestMatch == currentDomainNormalized && currentDomainNormalized != "" {
			// When the response has no answer and the NS records point
			// back to the same zone, verify this is actually an
			// authoritative response (AA flag). A non-authoritative
			// response with matching NS records indicates a lame
			// delegation — the server is not actually authoritative
			// for this zone and we should return SERVFAIL rather than
			// silently accepting the response (Cloudflare/Google both
			// return SERVFAIL for these cases).
			if len(response.Answer) == 0 && !response.Authoritative {
				log.Debugf("RECURSION: lame delegation detected for %s — NS records point to same zone but response is not authoritative", currentDomain)
				pool.DefaultMessagePool.Put(response)
				rr.lastDNSSECEDECode.Store(uint64(edns.EDECodeNoReachableAuthority))
				return nil, nil, nil, false, ecsResponse, config.RecursiveIndicator, false,
					fmt.Errorf("lame delegation: no reachable authority for %s", currentDomain)
			}
			nsSlice, extraSlice := response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, config.RecursiveIndicator, false, nil
		}

		// Update DNSSEC chain: extract DS from current delegation, prepare
		// for child zone verification in the next iteration.
		//
		// Delegation responses do not contain DNSKEY records — we must
		// explicitly query the current (parent) zone's nameservers for
		// its DNSKEY RRset before we can cryptographically verify the
		// child's DS RRSIGs.
		rr.updateDNSSECChain(ctx, response, currentDomain, bestMatch, nameservers, chain)

		// Save parent zone before updating — glue name validation uses
		// the parent zone (the zone that published the delegation),
		// not the delegated-to zone.
		parentDomain := currentDomain
		currentDomain = bestMatch + "."

		var nextNS []string
		for _, ns := range bestNSRecords {
			for _, rrec := range response.Extra {
				switch a := rrec.(type) {
				case *dns.A:
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						// Validate glue name is within the parent zone
						glueName := dnsutil.NormalizeDomain(a.Header().Name)
						parDom := dnsutil.NormalizeDomain(parentDomain)
						if glueName != parDom && !strings.HasSuffix(glueName, "."+parDom) && parDom != "" {
							continue
						}
						nextNS = append(nextNS, net.JoinHostPort(a.A.String(), config.DefaultDNSPort))
					}
				case *dns.AAAA:
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						glueName := dnsutil.NormalizeDomain(a.Header().Name)
						parDom := dnsutil.NormalizeDomain(parentDomain)
						if glueName != parDom && !strings.HasSuffix(glueName, "."+parDom) && parDom != "" {
							continue
						}
						nextNS = append(nextNS, net.JoinHostPort(a.AAAA.String(), config.DefaultDNSPort))
					}
				}
			}
		}

		// Use glue records directly when available; only fall back to
		// independent NS resolution when the delegation has no glue.
		if len(nextNS) == 0 {
			nextNS = rr.resolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth, forceTCP)
		}

		if len(nextNS) == 0 {
			nsSlice, extraSlice := response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, config.RecursiveIndicator, false, nil
		}

		nextNS = ShuffleSlice(nextNS)
		pool.DefaultMessagePool.Put(response)
		nameservers = nextNS
	}
}

// validateWithDNSSEC performs cryptographic DNSSEC validation on a response
// using the current trust chain state.
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

// updateDNSSECChain extracts DS records from a delegation response and
// updates the trust chain for the next delegation step.
//
// Delegation responses from authoritative servers do not include DNSKEY
// records — those must be queried separately. When chain.zoneDNSKEYs is
// empty (no verified DNSKEYs for the parent zone), this function queries
// the current nameservers for the parent zone's DNSKEY RRset and verifies
// it against the existing trust chain before verifying the child DS.
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

// ensureZoneDNSKEYs guarantees that chain.zoneDNSKEYs contains verified
// DNSKEY records for the given zone. If the keys are not already available
// (from cache or a previous validation step), it queries the zone's
// nameservers explicitly, verifies the DNSKEY RRset against the trust chain,
// and caches the result.
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

// verifyDelegationDSRRSIG cryptographically verifies DS records against the
// parent zone's verified DNSKEYs before accepting them as delegation proof.
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

// finalizeDNSSEC cryptographically validates an answer from authoritative
// nameservers. If the zone's DNSKEY is not yet verified, it queries for it
// explicitly, verifies against the parent DS (or self-signature for root),
// and then verifies the answer RRSIGs. Returns true only on full crypto success.
// On failure, sets chain.lastEDECode to the appropriate RFC 8914 EDE code.
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

// getZoneCutSigner returns the zone name of the first RRSIG in the answer
// section whose signer name is a proper subdomain of currentDomain. This
// identifies the actual child zone that signed the answer when a zone cut
// is detected.
func (rr *Recursive) getZoneCutSigner(response *dns.Msg, currentDomain string) string {
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

// resolveZoneCut builds the DNSSEC chain of trust for a delegated child zone
// when the authoritative server returns an answer signed by the child zone's
// keys instead of issuing a referral. It queries for the child zone's DS and
// DNSKEY records, verifies them against the parent's trusted keys, and
// validates the original answer against the child zone's verified DNSKEYs.
//
// Returns (validated, error). On success, validated indicates whether the
// answer passed DNSSEC verification. On error, the zone cut could not be
// resolved (e.g. DS/DNSKEY queries failed) and the answer should be returned
// without DNSSEC validation.
func (rr *Recursive) resolveZoneCut(ctx context.Context, response *dns.Msg, nameservers []string, question dns.Question, currentDomain string, ecs *edns.ECSOption, forceTCP bool, chain *dnssecChain) (bool, error) {
	crypto := rr.resolver.validator.Crypto

	// Extract the child zone name from the RRSIG signer
	childZone := rr.getZoneCutSigner(response, currentDomain)
	if childZone == "" {
		return false, fmt.Errorf("could not determine child zone name from RRSIG signer")
	}

	// Ensure we have verified DNSKEYs for the parent zone
	if len(chain.zoneDNSKEYs) == 0 {
		rr.ensureZoneDNSKEYs(ctx, nameservers, currentDomain, chain)
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
	dsQuestion := dns.Question{Name: dns.Fqdn(childZone), Qtype: dns.TypeDS, Qclass: dns.ClassINET}
	dsResp, dsErr := rr.queryNameserversConcurrent(ctx, nameservers, dsQuestion, ecs, forceTCP)
	if dsErr != nil {
		return false, fmt.Errorf("DS query for %s failed: %w", childZone, dsErr)
	}
	defer pool.DefaultMessagePool.Put(dsResp)

	dsRecords := security.FindDS(dsResp.Answer)
	dsRecords = append(dsRecords, security.FindDS(dsResp.Ns)...)
	if len(dsRecords) == 0 {
		return false, fmt.Errorf("no DS records found for %s", childZone)
	}

	// Verify DS RRSIGs against the parent zone's DNSKEYs
	allSigs := security.CollectRRSIGs(dsResp.Answer, dsResp.Ns, dsResp.Extra)
	dsRRSIGs := security.FindRRSIGs(allSigs, dns.Fqdn(childZone), dns.TypeDS)
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

	// Query for the child zone's DNSKEY records
	dnskeyQuestion := dns.Question{Name: dns.Fqdn(childZone), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	dnskeyResp, dnskeyErr := rr.queryNameserversConcurrent(ctx, nameservers, dnskeyQuestion, ecs, forceTCP)
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
	validated, valErr := crypto.ValidateResponse(response, childZone, dnskeyRecords)
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

// isZoneCut checks whether the answer RRSIGs in the response are signed by a
// zone different from currentDomain. This indicates the authoritative server
// returned an answer from a delegated child zone instead of a referral, and
// the recursive resolver should follow the delegation rather than failing
// DNSSEC validation against the wrong zone's keys.
func (rr *Recursive) isZoneCut(response *dns.Msg, currentDomain string) bool {
	return rr.getZoneCutSigner(response, currentDomain) != ""
}

func (rr *Recursive) handleSuspiciousResponse(reason string, currentlyTCP bool, _ context.Context, _ dns.Question, _ *edns.ECSOption, _ int) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	if !currentlyTCP {
		return nil, nil, nil, false, nil, "", true, fmt.Errorf("%w: %s", ErrHijackDetected, reason)
	}
	return nil, nil, nil, false, nil, "", true, fmt.Errorf("DNS hijacking detected (TCP): %s", reason)
}

func (rr *Recursive) queryNameserversConcurrent(ctx context.Context, nameservers []string, question dns.Question, ecs *edns.ECSOption, forceTCP bool) (*dns.Msg, error) {
	if len(nameservers) == 0 {
		return nil, errors.New("no nameservers")
	}

	queryCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(errors.New("query resolution completed"))

	resultChan := make(chan *dns.Msg, 1)
	g, queryCtx := errgroup.WithContext(queryCtx)
	g.SetLimit(concurrencyLimit(len(nameservers)))

	var activeConnections atomic.Int32

	for _, ns := range nameservers {
		nsAddr := ns
		protocol := "udp"
		if forceTCP {
			protocol = "tcp"
		}
		server := &config.UpstreamServer{Address: nsAddr, Protocol: protocol}

		g.Go(func() error {
			defer dnsutil.HandlePanic("Query nameserver")
			activeConnections.Add(1)
			defer activeConnections.Add(-1)

			select {
			case <-queryCtx.Done():
				return queryCtx.Err()
			default:
			}

			msg := rr.resolver.buildMsg(question, ecs, true, false)
			defer pool.DefaultMessagePool.Put(msg)

			subCtx, subCancel := context.WithTimeout(queryCtx, config.IdleTimeout/2)
			defer subCancel()

			result := rr.resolver.client.ExecuteQuery(subCtx, msg, server)
			if result.Error == nil && result.Response != nil {
				rcode := result.Response.Rcode
				if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
					select {
					case resultChan <- result.Response:
						cancel(errors.New("first win"))
						return nil
					case <-queryCtx.Done():
						pool.DefaultMessagePool.Put(result.Response)
						return queryCtx.Err()
					}
				}
				pool.DefaultMessagePool.Put(result.Response)
			}
			return nil
		})
	}

	go func() {
		_ = g.Wait()
		close(resultChan)
	}()

	select {
	case result, ok := <-resultChan:
		if ok && result != nil {
			return result, nil
		}
		return nil, errors.New("no successful response")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (rr *Recursive) resolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS, qname string, depth int, forceTCP bool) []string {
	if len(nsRecords) == 0 {
		return nil
	}

	nsRecords = ShuffleSlice(nsRecords)
	resolveCtx, resolveCancel := context.WithTimeout(ctx, config.IdleTimeout)
	defer resolveCancel()

	g, queryCtx := errgroup.WithContext(resolveCtx)
	g.SetLimit(concurrencyLimit(len(nsRecords)))

	var allMu sync.Mutex
	var allAddresses []string

	for _, ns := range nsRecords {
		nsRecord := ns
		g.Go(func() error {
			defer dnsutil.HandlePanic("Resolve NS addresses")
			select {
			case <-queryCtx.Done():
				return nil
			default:
			}

			if strings.EqualFold(strings.TrimSuffix(nsRecord.Ns, "."), strings.TrimSuffix(qname, ".")) {
				return nil
			}

			var nsAddrs []string

			aQuestion := dns.Question{Name: dns.Fqdn(nsRecord.Ns), Qtype: dns.TypeA, Qclass: dns.ClassINET}
			if ans, _, extra, _, _, _, _, err := rr.resolve(resolveCtx, aQuestion, nil, depth+1, forceTCP); err == nil {
				for _, rrec := range ans {
					if a, ok := rrec.(*dns.A); ok {
						nsAddrs = append(nsAddrs, net.JoinHostPort(a.A.String(), config.DefaultDNSPort))
					}
				}
				// Check Additional section for AAAA glue before making a separate query
				for _, rrec := range extra {
					if aaaa, ok := rrec.(*dns.AAAA); ok && strings.EqualFold(aaaa.Header().Name, nsRecord.Ns) {
						nsAddrs = append(nsAddrs, net.JoinHostPort(aaaa.AAAA.String(), config.DefaultDNSPort))
					}
				}
			}

			hasAaaa := false
			for _, addr := range nsAddrs {
				host, _, _ := net.SplitHostPort(addr)
				if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
					hasAaaa = true
					break
				}
			}
			if !hasAaaa {
				aaaaQuestion := dns.Question{Name: dns.Fqdn(nsRecord.Ns), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
				if ans, _, _, _, _, _, _, err := rr.resolve(resolveCtx, aaaaQuestion, nil, depth+1, forceTCP); err == nil {
					for _, rrec := range ans {
						if aaaa, ok := rrec.(*dns.AAAA); ok {
							nsAddrs = append(nsAddrs, net.JoinHostPort(aaaa.AAAA.String(), config.DefaultDNSPort))
						}
					}
				}
			}

			if len(nsAddrs) > 0 {
				allMu.Lock()
				allAddresses = append(allAddresses, nsAddrs...)
				allMu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()
	allMu.Lock()
	defer allMu.Unlock()
	return allAddresses
}
