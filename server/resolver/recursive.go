package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
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
					// Always record the DNSSEC EDE code for stats and client EDE hints,
					// even when enforcement is off.
					if len(chain.childDS) > 0 && !validated {
						rr.lastDNSSECEDECode.Store(uint64(chain.lastEDECode))
						if rr.resolver.DNSSECEnforce {
							log.Debugf("SECURITY: DNSSEC validation failed for %s — zone cut child has DS but RRSIG verification failed", question.Name)
							pool.DefaultMessagePool.Put(response)
							return nil, nil, nil, false, ecsResponse, config.RecursiveIndicator, false,
								fmt.Errorf("DNSSEC validation failed: bogus zone cut delegation for %s", question.Name)
						}
					}
				} else {
					log.Debugf("SECURITY: zone cut resolution failed for %s: %v", question.Name, cutErr)
					// Zone cut resolution failed (e.g. no DS, DS verification
					// failure). Always record the EDE code; return SERVFAIL only
					// when enforcement is on.
					if len(chain.childDS) > 0 {
						rr.lastDNSSECEDECode.Store(uint64(chain.lastEDECode))
						if rr.resolver.DNSSECEnforce {
							log.Debugf("SECURITY: DNSSEC validation failed for %s — zone cut resolution failed with DS present", question.Name)
							pool.DefaultMessagePool.Put(response)
							return nil, nil, nil, false, ecsResponse, config.RecursiveIndicator, false,
								fmt.Errorf("DNSSEC validation failed: zone cut resolution error for %s: %w", question.Name, cutErr)
						}
					}
					validated = false
				}
				answer, authority, additional := response.Answer, response.Ns, response.Extra
				pool.DefaultMessagePool.Put(response)
				return answer, authority, additional, validated, ecsResponse, config.RecursiveIndicator, false, nil
			} else {
				// When DNSSEC crypto is enabled and the zone has DS records in the
				// parent, a crypto verification failure means the answer is bogus.
				// Always record the EDE code for client hints and stats; return
				// SERVFAIL only when enforcement is on (RFC 4035).
				if len(chain.childDS) > 0 && !validated {
					rr.lastDNSSECEDECode.Store(uint64(chain.lastEDECode))
					if rr.resolver.DNSSECEnforce {
						log.Debugf("SECURITY: DNSSEC validation failed for %s — zone has DS but DNSKEY/RRSIG verification failed", question.Name)
						pool.DefaultMessagePool.Put(response)
						return nil, nil, nil, false, ecsResponse, config.RecursiveIndicator, false,
							fmt.Errorf("DNSSEC validation failed: bogus delegation for %s", question.Name)
					}
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
