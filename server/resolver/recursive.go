package resolver

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/defense"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Recursive performs iterative DNS resolution by walking the root, TLD, and
// authoritative nameserver hierarchy. When DNSSEC validation is enabled, it
// builds a cryptographic chain of trust at each delegation step.
//
// Both root servers and per-nameserver addresses share the same latency-sorted
// cache mechanism: per-type TypeA/TypeAAAA entries + ip_latency table.
// sortAnswerByLatency reorders records by latency at Get() time.
type Recursive struct {
	resolver          *Resolver
	lastDNSSECEDECode atomic.Uint64 // EDE code from the most recent DNSSEC validation failure
	cache             cache.Store
	ctx               context.Context // lifecycle context for background probes
}

// CNAME handles CNAME record chasing during DNS resolution, following the
// redirection chain up to config.DefaultMaxCNAMEChain hops. Defined in the same
// file as Recursive because CNAME resolution depends directly on recursive
// resolution (c.resolve → r.resolve). Splitting into a separate file would
// add unnecessary indirection without reducing coupling.
type CNAME struct {
	resolver *Resolver
}

// DNSSECEDECode returns the last DNSSEC EDE code atomically.
func (r *Recursive) DNSSECEDECode() uint16 {
	return uint16(r.lastDNSSECEDECode.Load()) //nolint:gosec // G115: EDE code — protocol-bounded uint16
}

// dnssecChain tracks the cryptographic trust chain state during recursive
// resolution. At each delegation level, verified parent DNSKEYs and child DS
// records are used to authenticate the child zone's DNSKEYs.
func (r *Recursive) resolve(ctx context.Context, question Question, ecs *edns.ECSOption, depth int, forceTCP bool) QueryResult {
	if depth > config.DefaultMaxRecursionDepth {
		log.Warnf("RECURSION: depth exceeded (depth=%d, max=%d) for %s", depth, config.DefaultMaxRecursionDepth, question.Name)
		return QueryResult{Cacheable: true, Err: fmt.Errorf("recursion depth exceeded: %d", depth)}
	}

	// Clear any stale DNSSEC EDE code from a previous CNAME hop or recursive
	// call. Without this, a DNSSEC failure in one hop can leak through a
	// successful validation in the next hop, causing false "bogus" verdicts.
	r.lastDNSSECEDECode.Store(0)

	qname := dnsutil.Fqdn(question.Name)
	question.Name = qname
	nameservers := r.getRootServers()
	currentDomain := "."
	normalizedQname := dnsutil.Canonical(qname)

	// hijackSeen is set to true when any VerdictHijack is observed at any
	// delegation level, including through internal TCP restarts.  The CNAME
	// resolver uses this to force TCP for subsequent CNAME targets.
	var hijackSeen bool

	// QNAME minimisation (RFC 9156). Only applied at the top-level resolve
	// call (depth == 0). Internal infrastructure queries (NS address
	// resolution, CNAME follow-up) use full QNAME.
	qnameMinimise := depth == 0 && r.resolver != nil
	var minimiseSteps int

	// tldServers saves the TLD nameservers for the hijack probe.
	var tldServers []string

	log.Debugf("RECURSION: depth=%d, querying %s (type=%s, tcp=%t, zone=%s, ns=%v)", depth, question.Name, dns.TypeToString[question.Qtype], forceTCP, currentDomain, nameservers)

	// Initialize DNSSEC trust chain with root trust anchors (when available).
	chain := &dnssecChain{}
	if crypto := r.resolver.validator.Crypto; crypto != nil {
		chain.parentDNSKEYs = crypto.RootKeys()
	}

	// Root-domain query (normalizedQname is empty for the root zone ".").
	if normalizedQname == "." {
		response, verdict, err := r.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP, currentDomain, r.resolver.validator.Hijack)
		if verdict == defense.VerdictHijack {
			hijackSeen = true
		}
		if err != nil {
			if verdict == defense.VerdictHijack && !forceTCP {
				qr := r.resolve(ctx, question, ecs, depth, true)
				qr.Hijack = true
				return qr
			}
			return QueryResult{Cacheable: true, Hijack: hijackSeen, Err: fmt.Errorf("root domain query: %w", err)}
		}
		cryptoValidated := r.isValidWithDNSSEC(response, currentDomain, chain)
		ecsResponse := r.resolver.edns.ParseFromDNS(response)
		answer, authority, additional := response.Answer, response.Ns, response.Extra
		pool.DefaultMessage.Put(response)
		return QueryResult{Cacheable: true, Answer: answer, Authority: authority, Additional: additional, Validated: cryptoValidated, ECS: ecsResponse, Server: config.RecursiveIndicator, Hijack: hijackSeen}
	}

	for {
		select {
		case <-ctx.Done():
			return QueryResult{Cacheable: true, Hijack: hijackSeen, Err: ctx.Err()}
		default:
		}

		var queryQuestion Question
		queryQuestion, minimiseSteps = r.applyQnameMinimisation(question, qname, currentDomain, qnameMinimise, minimiseSteps)

		// When QNAME minimisation exposes the full QNAME at a
		// non-authoritative zone (root/TLD/intermediate), probe
		// the servers we are about to query.  A legitimate
		// delegation server never returns A/AAAA for a
		// subdomain — if it does, the GFW is injecting at this
		// level; switch to TCP before querying.
		authoritativeForceTCP := forceTCP
		if !authoritativeForceTCP && qnameMinimise &&
			strings.EqualFold(queryQuestion.Name, qname) &&
			len(tldServers) > 0 {
			authoritativeForceTCP = r.probeTLDForHijack(ctx, tldServers, qname)
		}

		response, verdict, err := r.queryNameserversConcurrent(ctx, nameservers, queryQuestion, ecs, authoritativeForceTCP, currentDomain, r.resolver.validator.Hijack)

		// ── Single TCP fallback decision point ──────────────────────
		// If any response at this delegation level was flagged as
		// hijack, restart the ENTIRE resolution via TCP.  GFW cannot
		// inject TCP responses, so all subsequent levels (including
		// authoritative) are protected.
		if verdict == defense.VerdictHijack {
			hijackSeen = true
			if !forceTCP {
				if response != nil {
					pool.DefaultMessage.Put(response)
				}
				qr := r.resolve(ctx, question, ecs, depth, true)
				qr.Hijack = true
				return qr
			}
		}

		if err != nil {
			return QueryResult{Cacheable: true, Hijack: hijackSeen, Err: fmt.Errorf("query %s: %w", currentDomain, err)}
		}
		// ── End TCP fallback ────────────────────────────────────────

		// Cryptographic DNSSEC validation at this delegation level
		cryptoValidated := r.isValidWithDNSSEC(response, currentDomain, chain)
		ecsResponse := r.resolver.edns.ParseFromDNS(response)

		validated := cryptoValidated

		if r.shouldRetryMinimisedQname(queryQuestion.Name, qname, qnameMinimise, response, normalizedQname) {
			pool.DefaultMessage.Put(response)
			minimiseSteps = config.DefaultQnameMinimiseCount
			continue
		}

		if termRes := r.processAnswerWithDNSSEC(ctx, response, nameservers, question, currentDomain, ecs, forceTCP, chain, &validated, ecsResponse); termRes != nil {
			return *termRes
		}

		validated = r.validateNODATAWithNSEC(response, ctx, nameservers, currentDomain, chain, validated)

		bestMatch, bestNSRecords, cont, termRes := r.collectBestNSMatch(response, normalizedQname, queryQuestion.Name, qname, qnameMinimise, validated, ecsResponse)
		if termRes != nil {
			return *termRes
		}
		if cont {
			continue
		}
		if termRes := r.checkLameDelegation(response, currentDomain, bestMatch, validated, ecsResponse); termRes != nil {
			return *termRes
		}

		// Update DNSSEC chain: extract DS from current delegation, prepare
		// for child zone verification in the next iteration.
		//
		// Delegation responses do not contain DNSKEY records — we must
		// explicitly query the current (parent) zone's nameservers for
		// its DNSKEY RRset before we can cryptographically verify the
		// child's DS RRSIGs.
		r.updateDNSSECChain(ctx, response, currentDomain, bestMatch, nameservers, chain)

		// Save parent zone before updating — glue name validation uses
		// the parent zone (the zone that published the delegation),
		// not the delegated-to zone.
		parentDomain := currentDomain
		currentDomain = bestMatch

		// Resolve NS addresses for the next delegation level.
		nsResult := r.resolveNextNameservers(ctx, bestNSRecords, response, qname, parentDomain, depth, forceTCP)

		if len(nsResult.addrs) > 0 {
			log.Debugf("RECURSION: zone=%s, %d NS names -> %d addresses (source=%s): %v",
				currentDomain, len(bestNSRecords), len(nsResult.addrs), nsResult.source, nsResult.addrs)
		}

		if len(nsResult.addrs) == 0 {
			nsSlice, extraSlice := response.Ns, response.Extra
			pool.DefaultMessage.Put(response)
			return QueryResult{Cacheable: true, Authority: nsSlice, Additional: extraSlice, Validated: validated, ECS: ecsResponse, Server: config.RecursiveIndicator}
		}

		r.cacheGlueRecords(nsResult.glue)

		pool.DefaultMessage.Put(response)
		nameservers = nsResult.addrs
		// Save TLD servers after updating. Used for the
		// full-QNAME hijack probe at the authoritative step.
		if dnsutil.Labels(dnsutil.Fqdn(currentDomain)) == 1 {
			tldServers = nameservers
		}
	}
}

// probeTLDForHijack sends a single UDP probe to a TLD server for the full
// QNAME and delegates the verdict to security.Detector.IsHijackedByTLD.
func (r *Recursive) probeTLDForHijack(ctx context.Context, tldServers []string, qname string) bool {
	detector := r.resolver.validator.Hijack
	if detector == nil || !detector.IsEnabled() || len(tldServers) == 0 {
		return false
	}

	msg := pool.DefaultMessage.Get()
	defer pool.DefaultMessage.Put(msg)
	dnsutil.SetQuestion(msg, dnsutil.Fqdn(qname), dns.TypeA)
	msg.RecursionDesired = false
	msg.UDPSize = pool.RecursiveUDPBufferSize

	server := &config.UpstreamServer{
		Address:  tldServers[0],
		Protocol: config.ProtoUDP,
		Proxy:    r.resolver.recursiveProxyURL,
	}

	probeCtx, probeCancel := context.WithTimeout(ctx, config.DefaultHijackProbeTimeout)
	defer probeCancel()

	result := r.resolver.queryClient.ExecuteQuery(probeCtx, msg, server)
	if result.Error != nil || result.Response == nil {
		return false
	}
	defer pool.DefaultMessage.Put(result.Response)

	if detector.IsHijackedByTLD(result.Response, qname) {
		log.Debugf("RECURSION: poison probe detected A/AAAA for %s from TLD server %s, forcing TCP",
			qname, tldServers[0])
		return true
	}
	return false
}

func (c *CNAME) resolve(ctx context.Context, question Question, ecs *edns.ECSOption) QueryResult {
	var allAnswers []dns.RR
	var finalAuthority, finalAdditional []dns.RR
	var finalECSResponse *edns.ECSOption
	var usedServer string
	var hijackOccurred bool
	allValidated := true

	currentQuestion := question
	visitedCNAMEs := make(map[string]bool)
	cnameDepth := 0

	for cnameDepth = range config.DefaultMaxCNAMEChain {
		select {
		case <-ctx.Done():
			return QueryResult{Cacheable: true, Err: ctx.Err()}
		default:
		}

		currentName := dnsutil.Canonical(currentQuestion.Name)
		if visitedCNAMEs[currentName] {
			log.Warnf("RECURSION: CNAME loop detected for %s", currentName)
			return QueryResult{Cacheable: true, Err: fmt.Errorf("CNAME loop detected: %s", currentName)}
		}
		visitedCNAMEs[currentName] = true
		log.Debugf("RECURSION: CNAME step %d/%d: resolving %s %s", cnameDepth+1, config.DefaultMaxCNAMEChain, currentQuestion.Name, dns.TypeToString[currentQuestion.Qtype])

		// When hijack was detected anywhere in the CNAME chain,
		// subsequent CNAME targets also use TCP so GFW cannot
		// inject at the authoritative level (where hijack
		// detection can't distinguish real from spoofed answers).
		forceTCP := hijackOccurred

		qr := c.resolver.recursive.resolve(ctx, currentQuestion, ecs, 0, forceTCP)
		if qr.Err != nil {
			return QueryResult{Cacheable: true, Err: qr.Err}
		}

		if usedServer == "" {
			usedServer = qr.Server
		}
		if qr.Hijack {
			hijackOccurred = true
		}
		if !qr.Validated {
			allValidated = false
		}
		if qr.ECS != nil {
			finalECSResponse = qr.ECS
		}

		allAnswers = append(allAnswers, qr.Answer...)
		finalAuthority = qr.Authority
		finalAdditional = qr.Additional

		var nextCNAME *dns.CNAME
		hasTargetType := false
		for _, r := range qr.Answer {
			if cname, ok := r.(*dns.CNAME); ok {
				if strings.EqualFold(r.Header().Name, currentQuestion.Name) {
					nextCNAME = cname
				}
			} else if dns.RRToType(r) == currentQuestion.Qtype {
				hasTargetType = true
			}
		}

		if hasTargetType || currentQuestion.Qtype == dns.TypeCNAME || nextCNAME == nil {
			break
		}

		currentQuestion = Question{
			Name:   nextCNAME.Target,
			Qtype:  question.Qtype,
			Qclass: question.Qclass,
		}
		log.Debugf("RECURSION: CNAME chain: %s → %s", currentName, nextCNAME.Target)
	}

	if cnameDepth >= config.DefaultMaxCNAMEChain-1 {
		log.Warnf("RECURSION: CNAME chain exhausted (max=%d) for %s", config.DefaultMaxCNAMEChain, dnsutil.Canonical(question.Name))
	}
	return QueryResult{Cacheable: true, Answer: allAnswers, Authority: finalAuthority, Additional: finalAdditional, Validated: allValidated, ECS: finalECSResponse, Server: usedServer, Hijack: hijackOccurred}
}
