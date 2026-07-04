package resolver

import (
	"context"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

// finalizeResponse strips cross-zone records, pools the response, and returns
// the extracted sections for the CNAME resolver to follow independently.
func (r *Recursive) finalizeResponse(response *dns.Msg, currentDomain string, validated bool, ecsResponse *edns.ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	answer := stripCrossZoneRecords(response.Answer, response.Extra, currentDomain)
	nsSlice, extraSlice := response.Ns, response.Extra
	pool.DefaultMessagePool.Put(response)
	return answer, nsSlice, extraSlice, validated, ecsResponse, config.RecursiveIndicator, false, nil
}

// terminalResult holds the return values from collectBestNSMatch when no
// NS delegation records are found and the resolution should end.
type terminalResult struct {
	answer, authority, additional []dns.RR
	validated                     bool
	ecs                           *edns.ECSOption
	server                        string
	hijack                        bool
	err                           error
}

// collectBestNSMatch collects NS records from a DNS response's Authority and
// Answer sections and finds the best zone cut match for the query name.
// When no match is found, it either triggers a QNAME minimisation retry
// (continue=true) or returns a terminal result.
func (r *Recursive) collectBestNSMatch(response *dns.Msg, normalizedQname, queryName, qname string, qnameMinimise bool, validated bool, ecsResponse *edns.ECSOption) (bestMatch string, bestNSRecords []*dns.NS, shouldContinue bool, termRes *terminalResult) {
	var allRRSections []dns.RR
	allRRSections = append(allRRSections, response.Ns...)
	allRRSections = append(allRRSections, response.Answer...)

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
		if qnameMinimise && !strings.EqualFold(queryName, qname) {
			pool.DefaultMessagePool.Put(response)
			return "", nil, true, nil
		}
		nsSlice, extraSlice := response.Ns, response.Extra
		pool.DefaultMessagePool.Put(response)
		return "", nil, false, &terminalResult{
			answer: nil, authority: nsSlice, additional: extraSlice,
			validated: validated, ecs: ecsResponse,
			server: config.RecursiveIndicator, hijack: false, err: nil,
		}
	}
	return bestMatch, bestNSRecords, false, nil
}

// applyQnameMinimisation applies RFC 9156 QNAME minimisation to the query
// question. Returns the (possibly minimised) question and the updated step count.
func (r *Recursive) applyQnameMinimisation(question Question, qname, currentDomain string, qnameMinimise bool, minimiseSteps int) (Question, int) {
	if !qnameMinimise {
		return question, minimiseSteps
	}
	addLabels := labelsToAdd(qname, currentDomain, minimiseSteps,
		config.DefaultQnameMinimiseCount, config.DefaultMinimiseOneLabel)
	minQname := minimiseQNAME(qname, currentDomain, addLabels)
	if !strings.EqualFold(minQname, qname) {
		qtype := minimisationQtype(question.Qtype)
		log.Debugf("RECURSION: qname minimisation step=%d zone=%s, querying minimised name=%s type=%s",
			minimiseSteps, currentDomain, minQname, dns.TypeToString[qtype])
		return Question{Name: minQname, Qtype: qtype, Qclass: question.Qclass}, minimiseSteps + 1
	}
	return question, minimiseSteps
}

// checkLameDelegation detects lame delegations where NS records point back
// to the same zone but the response is not authoritative (AA flag not set).
// Returns a terminal result for the caller to return, or nil if not lame.
func (r *Recursive) checkLameDelegation(response *dns.Msg, currentDomain, bestMatch string, validated bool, ecsResponse *edns.ECSOption) *terminalResult {
	currentDomainNormalized := dnsutil.NormalizeDomain(currentDomain)
	if bestMatch != currentDomainNormalized || currentDomainNormalized == "" {
		return nil
	}
	if len(response.Answer) == 0 && !response.Authoritative {
		log.Debugf("RECURSION: lame delegation detected for %s — NS records point to same zone but response is not authoritative", currentDomain)
		pool.DefaultMessagePool.Put(response)
		r.lastDNSSECEDECode.Store(uint64(edns.EDECodeNoReachableAuthority))
		return &terminalResult{
			server: config.RecursiveIndicator, ecs: ecsResponse,
			err: fmt.Errorf("lame delegation: no reachable authority for %s", currentDomain),
		}
	}
	nsSlice, extraSlice := response.Ns, response.Extra
	pool.DefaultMessagePool.Put(response)
	return &terminalResult{
		authority: nsSlice, additional: extraSlice,
		validated: validated, ecs: ecsResponse,
		server: config.RecursiveIndicator,
	}
}

// validateNODATAWithNSEC verifies NSEC/NSEC3 denial-of-existence records
// for NODATA/NXDOMAIN responses against the zone's verified DNSKEYs (RFC 4035).
func (r *Recursive) validateNODATAWithNSEC(response *dns.Msg, ctx context.Context, nameservers []string, currentDomain string, chain *dnssecChain, validated bool) bool {
	if len(response.Answer) > 0 {
		return validated
	}
	if len(chain.zoneDNSKEYs) == 0 {
		r.ensureZoneDNSKEYs(ctx, nameservers, currentDomain, chain)
	}
	if len(chain.zoneDNSKEYs) > 0 {
		if nsecValidated, _ := r.resolver.validator.Crypto.IsResponseValid(response, currentDomain, chain.zoneDNSKEYs); nsecValidated {
			return true
		}
	}
	return validated
}

// shouldRetryMinimisedQname checks RFC 9156 §2.3: if a minimised QNAME query
// returns answer records for a different owner name, expose the full QNAME
// and retry with the same nameservers.
func (r *Recursive) shouldRetryMinimisedQname(queryName, qname string, qnameMinimise bool, response *dns.Msg, normalizedQname string) bool {
	if !qnameMinimise || strings.EqualFold(queryName, qname) || len(response.Answer) == 0 {
		return false
	}
	for _, rr := range response.Answer {
		if rr != nil && strings.EqualFold(dnsutil.NormalizeDomain(rr.Header().Name), normalizedQname) {
			return false
		}
	}
	return true
}

// processAnswerWithDNSSEC validates the answer section with DNSSEC, handles
// zone cut detection, and enforces bogus delegation policies. Returns a
// terminal result when the answer is ready, or nil to continue the
// delegation loop for NODATA/NXDOMAIN responses.
func (r *Recursive) processAnswerWithDNSSEC(ctx context.Context, response *dns.Msg, nameservers []string, question Question, currentDomain string, ecs *edns.ECSOption, forceTCP bool, chain *dnssecChain, validated *bool, ecsResponse *edns.ECSOption) *terminalResult {
	if len(response.Answer) == 0 {
		return nil
	}

	*validated = r.isDNSSECValid(ctx, response, nameservers, question, currentDomain, ecs, forceTCP, chain)

	if !*validated && chain.zoneCutDetected {
		chain.zoneCutDetected = false
		if cutValidated, cutErr := r.resolveZoneCut(ctx, response, nameservers, question, currentDomain, ecs, forceTCP, chain); cutErr == nil {
			*validated = cutValidated
			if err := r.recordDNSSECFailure(chain, *validated,
				fmt.Sprintf("bogus zone cut delegation for %s", question.Name)); err != nil {
				log.Debugf("SECURITY: DNSSEC validation failed for %s — zone cut child has DS but RRSIG verification failed", question.Name)
				return &terminalResult{server: config.RecursiveIndicator, ecs: ecsResponse, err: err}
			}
		} else {
			if len(chain.childDS) > 0 || chain.dsPresentButUnverified {
				r.lastDNSSECEDECode.Store(uint64(chain.lastEDECode))
				if r.resolver.DNSSECEnforce {
					return &terminalResult{server: config.RecursiveIndicator, ecs: ecsResponse,
						err: fmt.Errorf("DNSSEC validation failed: zone cut resolution error for %s: %w", question.Name, cutErr)}
				}
			}
			*validated = false
		}
		return &terminalResult{answer: stripCrossZoneRecords(response.Answer, response.Extra, currentDomain),
			authority: response.Ns, additional: response.Extra,
			validated: *validated, ecs: ecsResponse, server: config.RecursiveIndicator}
	}

	if (len(chain.childDS) > 0 || chain.dsPresentButUnverified) && !*validated {
		r.lastDNSSECEDECode.Store(uint64(chain.lastEDECode))
		if r.resolver.DNSSECEnforce {
			return &terminalResult{server: config.RecursiveIndicator, ecs: ecsResponse,
				err: fmt.Errorf("DNSSEC validation failed: bogus delegation for %s", question.Name)}
		}
	}
	return &terminalResult{answer: stripCrossZoneRecords(response.Answer, response.Extra, currentDomain),
		authority: response.Ns, additional: response.Extra,
		validated: *validated, ecs: ecsResponse, server: config.RecursiveIndicator}
}
