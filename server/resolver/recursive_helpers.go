package resolver

import (
	"context"
	"fmt"
	"strings"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// collectBestNSMatch collects NS records from a DNS response's Authority and
// Answer sections and finds the best zone cut match for the query name.
// When no match is found, it either triggers a QNAME minimisation retry
// (continue=true) or returns a terminal result.
func (r *Recursive) collectBestNSMatch(response *dns.Msg, normalizedQname, queryName, qname string, qnameMinimise, validated bool, ecsResponse *edns.ECSOption) (bestMatch string, bestNSRecords []*dns.NS, shouldContinue bool, termRes *QueryResult) {
	allRRSections := make([]dns.RR, 0, len(response.Ns)+len(response.Answer))
	allRRSections = append(allRRSections, response.Ns...)
	allRRSections = append(allRRSections, response.Answer...)

	for _, rrec := range allRRSections {
		if ns, ok := rrec.(*dns.NS); ok {
			nsName := dnsutil.Canonical(rrec.Header().Name)
			isMatch := dnsutil.IsBelow(dnsutil.Fqdn(nsName), dnsutil.Fqdn(normalizedQname))
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
			pool.DefaultMessage.Put(response)
			return "", nil, true, nil
		}
		// Deep-copy before Put — pooled message backing array is reused.
		nsSlice := make([]dns.RR, len(response.Ns))
		copy(nsSlice, response.Ns)
		extraSlice := make([]dns.RR, len(response.Extra))
		copy(extraSlice, response.Extra)
		rcode := response.Rcode
		pool.DefaultMessage.Put(response)
		return "", nil, false, &QueryResult{
			Cacheable: true,
			Answer:    nil, Authority: nsSlice, Additional: extraSlice,
			Rcode: rcode, Validated: validated, ECS: ecsResponse,
			Server: config.ProtoRecursive, Poisoned: false, Err: nil,
		}
	}
	return bestMatch, bestNSRecords, false, nil
}

// applyQnameMinimisation applies RFC 9156 QNAME minimisation to the query
// question. Returns the (possibly minimised) question and the updated step count.
func (r *Recursive) applyQnameMinimisation(question Question, qname, currentDomain string, qnameMinimise bool, minimiseSteps int) (q Question, steps int) {
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

// isApexSOANODATA reports whether the response is an authoritative NODATA
// whose SOA owner is the queried name.  A parent server that also hosts the
// child zone on the same platform answers a minimised query for a delegated
// name from its child-zone copy (aa + SOA at the qname) instead of referring;
// the SOA proves the qname is a zone apex, i.e. a zone cut.
func isApexSOANODATA(response *dns.Msg, queryName string) bool {
	if response == nil || !response.Authoritative || len(response.Answer) > 0 {
		return false
	}
	for _, rr := range response.Ns {
		if soa, ok := rr.(*dns.SOA); ok && dns.EqualName(dnsutil.Fqdn(soa.Header().Name), dnsutil.Fqdn(queryName)) {
			return true
		}
	}
	return false
}

// advanceApexZoneCut advances the walk through a zone cut revealed by an
// authoritative NODATA at the minimised qname (see isApexSOANODATA).  The
// qname's NS RRset is fetched from the same servers and the delegation is
// processed through the DNSSEC chain like any other zone cut.  Returns the
// next-level nameservers and zone, or ok=false when the cut cannot be
// established and the caller should keep exposing labels.
func (r *Recursive) advanceApexZoneCut(ctx context.Context, queryName string, nameservers []string, currentDomain string, ecs *edns.ECSOption, chain *dnssecChain, depth int, forceTCP bool, qname string) (nextNS []string, nextZone string, ok bool) {
	nsQuestion := Question{Name: dnsutil.Fqdn(queryName), Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	nsResp, _, err := r.queryNameserversConcurrent(ctx, nameservers, nsQuestion, nil, ecs, forceTCP, currentDomain, r.resolver.validator.Poisonguard)
	if err != nil || nsResp == nil {
		log.Debugf("RECURSION: NS query for zone-cut candidate %s failed: %v", queryName, err)
		return nil, "", false
	}
	defer pool.DefaultMessage.Put(nsResp)

	// The NS RRset may appear in the Answer section (same server hosts both
	// parent and child zones) or in a referral's Authority section.
	var nsRecords []*dns.NS
	for _, rrec := range append(nsResp.Ns, nsResp.Answer...) {
		if ns, isNS := rrec.(*dns.NS); isNS && dns.EqualName(dnsutil.Fqdn(rrec.Header().Name), dnsutil.Fqdn(queryName)) {
			nsRecords = append(nsRecords, ns)
		}
	}
	if len(nsRecords) == 0 {
		log.Debugf("RECURSION: no NS records for zone-cut candidate %s", queryName)
		return nil, "", false
	}

	nsResult := r.resolveNextNameservers(ctx, nsRecords, nsResp, qname, currentDomain, depth, forceTCP)
	if len(nsResult.addrs) == 0 {
		// The cut cannot be established — return without touching the
		// chain, so the walk's parent-zone state stays intact for the next
		// iteration.
		log.Debugf("RECURSION: no reachable addresses for zone-cut candidate %s", queryName)
		return nil, "", false
	}
	// Only mutate the chain once the cut is established: a partially
	// updated chain for a zone the walk never reaches could make the next
	// iteration validate parent responses against the candidate zone's
	// keys or treat a would-be-insecure delegation as unverifiable.
	r.updateDNSSECChain(ctx, nsResp, currentDomain, queryName, nameservers, chain)
	r.cacheGlueRecords(nsResult.glue)
	log.Debugf("RECURSION: zone=%s via authoritative-NODATA zone cut, %d NS names -> %d addresses (source=%s): %v",
		queryName, len(nsRecords), len(nsResult.addrs), nsResult.source, nsResult.addrs)
	return nsResult.addrs, dnsutil.Canonical(queryName), true
}

// checkLameDelegation detects lame delegations where NS records point back
// to the same zone but the response is not authoritative (AA flag not set).
// Returns a terminal result for the caller to return, or nil if not lame.
func (r *Recursive) checkLameDelegation(response *dns.Msg, currentDomain, bestMatch string, validated bool, ecsResponse *edns.ECSOption) *QueryResult {
	currentDomainNormalized := dnsutil.Canonical(currentDomain)
	if bestMatch != currentDomainNormalized || currentDomainNormalized == "." {
		return nil
	}
	if len(response.Answer) == 0 && !response.Authoritative {
		log.Debugf("RECURSION: lame delegation detected for %s — NS records point to same zone but response is not authoritative", currentDomain)
		pool.DefaultMessage.Put(response)
		return &QueryResult{
			Cacheable: true,
			Server:    config.ProtoRecursive, ECS: ecsResponse,
			Err:       fmt.Errorf("lame delegation: no reachable authority for %s", currentDomain),
			DNSSECEDE: dns.ExtendedErrorNoReachableAuthority,
		}
	}
	// Deep-copy before Put: the pooled msg is returned to the pool for
	// reuse by another goroutine. RR objects are independently allocated
	// (Unpack does not alias the wire buffer), so the copied slices stay
	// valid — the copy documents that invariant and guards against future
	// pool/Unpack changes (internal/pool/pool.go Put semantics).
	nsSlice := make([]dns.RR, len(response.Ns))
	copy(nsSlice, response.Ns)
	extraSlice := make([]dns.RR, len(response.Extra))
	copy(extraSlice, response.Extra)
	pool.DefaultMessage.Put(response)
	return &QueryResult{
		Cacheable: true,
		Authority: nsSlice, Additional: extraSlice,
		Validated: validated, ECS: ecsResponse,
		Server: config.ProtoRecursive,
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
		nsecValidated, valErr := r.resolver.validator.Crypto.IsResponseValid(response, currentDomain, chain.zoneDNSKEYs)
		if valErr != nil {
			log.Debugf("SECURITY: NSEC validation error for %s: %v", currentDomain, valErr)
		}
		if nsecValidated {
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
		if rr != nil && strings.EqualFold(dnsutil.Canonical(rr.Header().Name), normalizedQname) {
			return false
		}
	}
	return true
}

// processAnswerWithDNSSEC validates the answer section with DNSSEC, handles
// zone cut detection, and enforces bogus delegation policies. Returns a
// terminal result when the answer is ready, or nil to continue the
// delegation loop for NODATA/NXDOMAIN responses.
func (r *Recursive) processAnswerWithDNSSEC(ctx context.Context, response *dns.Msg, nameservers []string, question Question, currentDomain string, ecs *edns.ECSOption, forceTCP bool, chain *dnssecChain, validated *bool, ecsResponse *edns.ECSOption) *QueryResult {
	if len(response.Answer) == 0 {
		return nil
	}

	*validated = r.isDNSSECValid(ctx, response, nameservers, question, currentDomain, ecs, forceTCP, chain)

	if !*validated && chain.zoneCutDetected {
		chain.zoneCutDetected = false
		// The parent zone's DS records are for the parent→child
		// delegation; they do not apply to sub-zones discovered
		// via RRSIG signer mismatch. Clear them so failed zone
		// cut resolution is treated as insecure, not bogus.

		if cutValidated, cutErr := r.resolveZoneCut(ctx, response, nameservers, question, currentDomain, ecs, forceTCP, chain); cutErr == nil {
			*validated = cutValidated
			if err := r.recordDNSSECFailure(chain, *validated,
				"bogus zone cut delegation for "+question.Name); err != nil {
				log.Debugf("SECURITY: DNSSEC validation failed for %s — zone cut child has DS but RRSIG verification failed", question.Name)
				pool.DefaultMessage.Put(response)
				return &QueryResult{Cacheable: true, Server: config.ProtoRecursive, ECS: ecsResponse, Err: err, DNSSECEDE: chain.lastEDECode}
			}
		} else {
			log.Debugf("SECURITY: zone cut resolution failed for %s: %v (treating as insecure)", question.Name, cutErr)
			*validated = false
		}
		answer := stripCrossZoneRecords(response.Answer, response.Extra, currentDomain)
		auth := make([]dns.RR, len(response.Ns))
		copy(auth, response.Ns)
		extra := make([]dns.RR, len(response.Extra))
		copy(extra, response.Extra)
		pool.DefaultMessage.Put(response)
		return &QueryResult{
			Cacheable: true,
			Answer:    answer,
			Authority: auth, Additional: extra,
			Validated: *validated, ECS: ecsResponse, Server: config.ProtoRecursive,
		}
	}

	if (len(chain.childDS) > 0 || chain.dsPresentButUnverified) && !*validated {
		// RRSIGs missing from an otherwise-valid DNSSEC chain means the
		// zone has verified DNSKEYs but the individual records aren't
		// signed (e.g. Cloudflare challenge subdomains).  Treat as
		// insecure, not bogus — same behaviour as 1.1.1.1.
		if r.resolver.DNSSECEnforce && chain.lastEDECode != dns.ExtendedErrorRRSIGsMissing {
			pool.DefaultMessage.Put(response)
			return &QueryResult{
				Cacheable: true,
				Server:    config.ProtoRecursive, ECS: ecsResponse,
				Err:       fmt.Errorf("DNSSEC validation failed: bogus delegation for %s", question.Name),
				DNSSECEDE: chain.lastEDECode,
			}
		}
	}
	answer := stripCrossZoneRecords(response.Answer, response.Extra, currentDomain)
	auth := make([]dns.RR, len(response.Ns))
	copy(auth, response.Ns)
	extra := make([]dns.RR, len(response.Extra))
	copy(extra, response.Extra)
	pool.DefaultMessage.Put(response)
	return &QueryResult{
		Cacheable: true,
		Answer:    answer,
		Authority: auth, Additional: extra,
		Validated: *validated, ECS: ecsResponse, Server: config.ProtoRecursive,
	}
}

// extractGlueIP extracts an IP address string from a glue record (A or AAAA)
// when the record name matches the given NS name. Returns ("", false) on mismatch.
func extractGlueIP(rr dns.RR, nsName string) (string, bool) {
	if !strings.EqualFold(rr.Header().Name, nsName) {
		return "", false
	}
	switch a := rr.(type) {
	case *dns.A:
		return a.A.String(), true
	case *dns.AAAA:
		return a.AAAA.String(), true
	default:
		return "", false
	}
}
