// CNAME-chain resolution: following chains with the iteration budget,
// detecting followed aliases, and the TLD poison probe.

package resolver

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// CNAME handles CNAME record chasing during DNS resolution, following the
// redirection chain up to config.DefaultMaxCNAMEChain hops. Defined in the same
// file as Recursive because CNAME resolution depends directly on recursive
// resolution (c.resolve → r.resolve). Splitting into a separate file would
// add unnecessary indirection without reducing coupling.
type CNAME struct {
	resolver *Resolver
}

// cnameAliasFollowed reports whether a CNAME's owner is the target of any
// other CNAME in the answer (i.e. it is an intermediate hop of a chain being
// followed, not a separate alias).
func cnameAliasFollowed(c *dns.CNAME, answer []dns.RR) bool {
	for _, r := range answer {
		if other, ok := r.(*dns.CNAME); ok && other != c {
			if strings.EqualFold(dnsutil.Fqdn(other.Target), dnsutil.Fqdn(c.Header().Name)) {
				return true
			}
		}
	}
	return false
}

// findChainStep inspects one CNAME-chain step's answer: the CNAME owned by
// the queried name (nil when the chain ends here) and whether the answer
// carries terminal records owned by the queried name ITSELF.  A type-only
// terminal check is wrong: an authority that bundles the whole chain into one
// response (CNAME → CNAME → … + terminal A records, RFC 1034 §3.6.2 — e.g.
// CDN aliases like www.iqiyi.com) would otherwise stop the chain on terminal
// records owned by the CNAME target — records the owner-scoped collection in
// resolveInner then drops, serving a CNAME-only answer.  Both the collection
// and the break condition must be owner-scoped.
func findChainStep(answer []dns.RR, question Question) (nextCNAME *dns.CNAME, hasTargetType bool) {
	for _, r := range answer {
		if cname, ok := r.(*dns.CNAME); ok {
			if strings.EqualFold(r.Header().Name, question.Name) {
				nextCNAME = cname
			}
		} else if dns.RRToType(r) == question.Qtype &&
			strings.EqualFold(r.Header().Name, question.Name) {
			hasTargetType = true
		}
	}
	return nextCNAME, hasTargetType
}

// probeTLDForPoison probes the first few TLD servers concurrently for the
// full QNAME and delegates the verdict to security.Detector.IsPoisonedByTLD.
// Any peer's A/AAAA answer is injection evidence (a TLD server never
// legitimately answers a subdomain), so any poisoned verdict forces TCP; the
// concurrent fan-out covers single-server drops that would otherwise
// stretch the probe to its full timeout.
func (r *Recursive) probeTLDForPoison(ctx context.Context, tldServers []string, qname string) bool {
	if !r.poisonguard || len(tldServers) == 0 {
		return false
	}

	probeCtx, probeCancel := context.WithTimeout(ctx, config.DefaultPoisonProbeTimeout)
	defer probeCancel()

	// The walk's address list is unfiltered (it also seeds tldServers for
	// later levels) — skip the unreachable family here too.
	tldServers = filterByFamily(tldServers, r.addressFamily)
	n := min(len(tldServers), config.DefaultPoisonProbeServers)
	verdicts := make(chan bool, n)
	for i := range n {
		server := &config.UpstreamServer{
			Address:  tldServers[i],
			Protocol: config.ProtoUDP,
			Proxy:    r.resolver.recursiveProxyURL,
		}
		go func() {
			defer zdnsutil.HandlePanic("TLD poison probe")
			msg := pool.DefaultMessage.Get()
			defer pool.DefaultMessage.Put(msg)
			dnsutil.SetQuestion(msg, dnsutil.Fqdn(qname), dns.TypeA)
			msg.RecursionDesired = false
			msg.UDPSize = pool.RecursiveUDPBufferSize

			result := r.resolver.queryClient.ExecuteQuery(probeCtx, msg, server)
			if result.Error != nil || result.Response == nil {
				verdicts <- false
				return
			}
			defer pool.DefaultMessage.Put(result.Response)
			if r.resolver.validator.Poisonguard.IsPoisonedByTLD(result.Response, qname) {
				log.Debugf("RECURSION: poison probe detected A/AAAA for %s from TLD server %s, forcing TCP",
					qname, tldServers[i])
				verdicts <- true
				return
			}
			verdicts <- false
		}()
	}
	// Drain as verdicts arrive (buffered — every probe sends exactly one).
	// A single poisoned verdict is conclusive: return immediately, letting
	// the deferred probeCancel abort the remaining probes instead of
	// waiting out their timeouts alongside the concurrent data query.
	for range n {
		if <-verdicts {
			return true
		}
	}
	return false
}

func (c *CNAME) resolve(ctx context.Context, question Question, ecs *edns.ECSOption) QueryResult {
	// No singleflight dedup: every query walks independently.  The delegation
	// cache (in-memory LRU + spill) and the NS-address cache still deduplicate across queries
	// once a walk completes; in-flight coalescing via pending.ResultGroup was
	// removed because its follower-promotion ran duplicate full walks without
	// an overall deadline, amplifying any bottleneck (spill-tier disk reads, network)
	// into a goroutine explosion under load (2026-08 production incidents).
	return c.resolveInner(ctx, question, ecs)
}

// resolveInner performs the actual CNAME-chain resolution.
func (c *CNAME) resolveInner(ctx context.Context, question Question, ecs *edns.ECSOption) QueryResult {
	var allAnswers []dns.RR
	var finalAuthority, finalAdditional []dns.RR
	var finalECSResponse *edns.ECSOption
	var usedServer string
	var poisonOccurred bool
	allValidated := true
	var finalRcode uint16
	var allDNSSECEDE uint16
	truncated := false

	currentQuestion := question
	var visitedCNAMEs [config.DefaultMaxCNAMEChain]string
	visitedCount := 0

	chainExhausted := true
	for cnameDepth := range config.DefaultMaxCNAMEChain {
		select {
		case <-ctx.Done():
			return QueryResult{Cacheable: true, Err: ctx.Err()}
		default:
		}

		currentName := zdnsutil.Canonical(currentQuestion.Name)
		if slices.Contains(visitedCNAMEs[:visitedCount], currentName) {
			log.Debugf("RECURSION: CNAME loop detected for %s", currentName)
			return QueryResult{Cacheable: true, Err: fmt.Errorf("CNAME loop detected: %s", currentName)}
		}
		visitedCNAMEs[visitedCount] = currentName
		visitedCount++
		log.Debugf("RECURSION: CNAME step %d/%d: resolving %s %s", cnameDepth+1, config.DefaultMaxCNAMEChain, currentQuestion.Name, dns.TypeToString[currentQuestion.Qtype])

		// When hijack was detected anywhere in the CNAME chain,
		// subsequent CNAME targets also use TCP so GFW cannot
		// inject at the authoritative level (where hijack
		// detection can't distinguish real from spoofed answers).
		forceTCP := poisonOccurred

		qr := c.resolver.recursive.resolve(ctx, currentQuestion, ecs, 0, forceTCP)
		if qr.Err != nil {
			return QueryResult{Cacheable: true, Err: qr.Err}
		}
		if qr.Truncated {
			// Any step's TC signal must reach the client — retry logic
			// depends on it (M-low).
			truncated = true
		}

		if usedServer == "" {
			usedServer = qr.Server
		}
		if qr.DNSSECEDE != 0 {
			allDNSSECEDE = qr.DNSSECEDE
		}
		if qr.Poisoned {
			poisonOccurred = true
		}
		if !qr.Validated {
			allValidated = false
		}
		if qr.ECS != nil {
			finalECSResponse = qr.ECS
		}
		finalRcode = qr.Rcode

		for _, rr := range qr.Answer {
			h := rr.Header()
			// Keep every CNAME that participates in the chain (owner is an
			// alias being followed), not just the current owner — a
			// synthesized multi-hop chain (CNAME1 → CNAME2 → A) would
			// otherwise lose the intermediate CNAMEs.
			if cname, ok := rr.(*dns.CNAME); ok {
				if strings.EqualFold(h.Name, currentQuestion.Name) || cnameAliasFollowed(cname, qr.Answer) {
					// Dedup: an intermediate hop's CNAME is collected once as
					// an alias target and again as the next step's owner —
					// serve it once (the chain now follows bundled multi-hop
					// answers instead of breaking on type-only matches).
					dup := false
					for _, existing := range allAnswers {
						if ec, ok := existing.(*dns.CNAME); ok && strings.EqualFold(ec.Header().Name, h.Name) {
							dup = true
							break
						}
					}
					if !dup {
						allAnswers = append(allAnswers, rr)
					}
				}
				continue
			}
			// Owner must be the current CNAME target: a type-only match
			// would surface unrelated same-type records from other owners
			// into the chain (M-low).
			if strings.EqualFold(h.Name, currentQuestion.Name) {
				allAnswers = append(allAnswers, rr)
			}
		}
		finalAuthority = qr.Authority
		finalAdditional = qr.Additional

		nextCNAME, hasTargetType := findChainStep(qr.Answer, currentQuestion)

		if hasTargetType || currentQuestion.Qtype == dns.TypeCNAME || nextCNAME == nil {
			chainExhausted = false
			break
		}

		currentQuestion = Question{
			Name:   nextCNAME.Target,
			Qtype:  question.Qtype,
			Qclass: question.Qclass,
		}
		log.Debugf("RECURSION: CNAME chain: %s → %s", currentName, nextCNAME.Target)
	}

	if chainExhausted {
		log.Debugf("RECURSION: CNAME chain exhausted (max=%d) for %s", config.DefaultMaxCNAMEChain, zdnsutil.Canonical(question.Name))
	}
	return QueryResult{Cacheable: true, Answer: allAnswers, Authority: finalAuthority, Additional: finalAdditional, Rcode: finalRcode, Validated: allValidated, ECS: finalECSResponse, Server: usedServer, Poisoned: poisonOccurred, DNSSECEDE: allDNSSECEDE, Truncated: truncated}
}
