package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/probe"
	"zjdns/server/security"

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
}

// CNAME handles CNAME record chasing during DNS resolution, following the
// redirection chain up to config.DefaultMaxCNAMEChain hops. Defined in the same
// file as Recursive because CNAME resolution depends directly on recursive
// resolution (c.resolve → r.resolve). Splitting into a separate file would
// add unnecessary indirection without reducing coupling.
type CNAME struct {
	resolver *Resolver
}

// rootHints maps root server names to their addresses. Used as bootstrap
// on cold start; once cached, getRootServers uses the normal NS lookup path
// (lookupNSAddrsFromCache -> sortAnswerByLatency via ip_latency).
var rootHints = map[string][]string{
	"a.root-servers.net.": {"198.41.0.4:53", "[2001:503:ba3e::2:30]:53"},
	"b.root-servers.net.": {"170.247.170.2:53", "[2801:1b8:10::b]:53"},
	"c.root-servers.net.": {"192.33.4.12:53", "[2001:500:2::c]:53"},
	"d.root-servers.net.": {"199.7.91.13:53", "[2001:500:2d::d]:53"},
	"e.root-servers.net.": {"192.203.230.10:53", "[2001:500:a8::e]:53"},
	"f.root-servers.net.": {"192.5.5.241:53", "[2001:500:2f::f]:53"},
	"g.root-servers.net.": {"192.112.36.4:53", "[2001:500:12::d0d]:53"},
	"h.root-servers.net.": {"198.97.190.53:53", "[2001:500:1::53]:53"},
	"i.root-servers.net.": {"192.36.148.17:53", "[2001:7fe::53]:53"},
	"j.root-servers.net.": {"192.58.128.30:53", "[2001:503:c27::2:30]:53"},
	"k.root-servers.net.": {"193.0.14.129:53", "[2001:7fd::1]:53"},
	"l.root-servers.net.": {"199.7.83.42:53", "[2001:500:9f::42]:53"},
	"m.root-servers.net.": {"202.12.27.33:53", "[2001:dc3::35]:53"},
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
	normalizedQname := zdnsutil.NormalizeDomain(qname)

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
	if normalizedQname == "" {
		response, verdict, err := r.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP, currentDomain, r.resolver.validator.Hijack)
		if verdict == security.VerdictHijack {
			hijackSeen = true
		}
		if err != nil {
			if verdict == security.VerdictHijack && !forceTCP {
				qr := r.resolve(ctx, question, ecs, depth, true)
				qr.Hijack = true
				return qr
			}
			return QueryResult{Cacheable: true, Hijack: hijackSeen, Err: fmt.Errorf("root domain query: %w", err)}
		}
		cryptoValidated := r.isValidWithDNSSEC(response, currentDomain, chain)
		ecsResponse := r.resolver.edns.ParseFromDNS(response)
		answer, authority, additional := response.Answer, response.Ns, response.Extra
		pool.DefaultMessagePool.Put(response)
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
		if verdict == security.VerdictHijack {
			hijackSeen = true
			if !forceTCP {
				if response != nil {
					pool.DefaultMessagePool.Put(response)
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
			pool.DefaultMessagePool.Put(response)
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
		currentDomain = bestMatch + "."

		// Try cache first for all NS names — latency-sorted records
		// from previous resolutions (or restarted snapshots) skip the
		// glue extraction + inline probe entirely.
		var nextNS []string
		var nextNSSource string // "cache" or "glue" or "resolution"
		if r.cache != nil {
			for _, ns := range bestNSRecords {
				nsName := dnsutil.Fqdn(ns.Ns)
				cached := r.lookupNSAddrsFromCache(nsName, nil)
				if len(cached) > 0 {
					nextNS = append(nextNS, cached...)
					// Log per-NS latency ranking (fastest first) so
					// operators can verify the probe is working.
					if len(cached) > 1 && log.Default.Level() >= log.Debug {
						rankParts := make([]string, 0, len(cached))
						for i, addr := range cached {
							rankParts = append(rankParts, fmt.Sprintf("#%d=%s", i+1, addr))
						}
						log.Debugf("RECURSION: NS %s cached (sorted): %s", nsName, strings.Join(rankParts, " "))
					}
				}
			}
			if len(nextNS) > 0 {
				nextNSSource = "cache"
			}
		}

		// Fall back to glue records when cache doesn't cover all NS names.
		nsGlue := make(map[string][]dns.RR) // NS name → A/AAAA glue records
		if len(nextNS) == 0 {
			for _, ns := range bestNSRecords {
				for _, rrec := range response.Extra {
					ip, ok := extractGlueIP(rrec, ns.Ns)
					if !ok {
						continue
					}
					// Validate glue name is within the parent zone.
					rrecName := zdnsutil.NormalizeDomain(rrec.Header().Name)
					parDom := zdnsutil.NormalizeDomain(parentDomain)
					if rrecName != parDom && !strings.HasSuffix(rrecName, "."+parDom) && parDom != "" {
						continue
					}
					nsKey := dnsutil.Fqdn(rrec.Header().Name)
					nsGlue[nsKey] = append(nsGlue[nsKey], rrec)
					nextNS = append(nextNS, net.JoinHostPort(ip, config.DefaultDNSPort))
				}
			}
		}

		// Use glue records directly when available; only fall back to
		// independent NS resolution when the delegation has no glue.
		if len(nextNS) == 0 {
			nextNS = r.resolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth, forceTCP)
			if len(nextNS) > 0 {
				nextNSSource = "resolution"
			}
		} else if nextNSSource == "" {
			nextNSSource = "glue"
		}

		// Log the addresses being used for this delegation step so operators
		// can verify latency ordering. The first address is queried first
		// (within the concurrency limit); with first-win semantics, faster
		// servers win races.
		if len(nextNS) > 0 {
			log.Debugf("RECURSION: zone=%s, %d NS names → %d addresses (source=%s): %v",
				currentDomain, len(bestNSRecords), len(nextNS), nextNSSource, nextNS)
		}

		if len(nextNS) == 0 {
			nsSlice, extraSlice := response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return QueryResult{Cacheable: true, Authority: nsSlice, Additional: extraSlice, Validated: validated, ECS: ecsResponse, Server: config.RecursiveIndicator}
		}

		// Cache A/AAAA glue records per NS name immediately so
		// future queries hit warm cache. A background latency probe
		// will reorder them later — the current query uses addresses
		// as-is to avoid blocking the resolution pipeline.
		if r.cache != nil && len(nsGlue) > 0 {
			for nsName, records := range nsGlue {
				if len(records) > 0 {
					qtype := dns.RRToType(records[0])
					r.cache.Set(nsName, qtype, dns.ClassINET, nil, false, records, nil, nil, false)
				}
			}
			// Fire background latency probe for each NS name in the glue.
			for _, records := range nsGlue {
				addrs := addrsFromRRs(records)
				go probe.ProbeNSAddrs(r.cache, addrs)
			}
		}

		pool.DefaultMessagePool.Put(response)
		nameservers = nextNS
		// Save TLD servers after updating. Used for the
		// full-QNAME hijack probe at the authoritative step.
		if labelCount(currentDomain) == 1 {
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

	msg := pool.DefaultMessagePool.Get()
	defer pool.DefaultMessagePool.Put(msg)
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

	result := r.resolver.client.ExecuteQuery(probeCtx, msg, server)
	if result.Error != nil || result.Response == nil {
		return false
	}
	defer pool.DefaultMessagePool.Put(result.Response)

	if detector.IsHijackedByTLD(result.Response, qname) {
		log.Debugf("RECURSION: hijack probe detected A/AAAA for %s from TLD server %s, forcing TCP",
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

		currentName := zdnsutil.NormalizeDomain(currentQuestion.Name)
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
		log.Warnf("RECURSION: CNAME chain exhausted (max=%d) for %s", config.DefaultMaxCNAMEChain, zdnsutil.NormalizeDomain(question.Name))
	}
	return QueryResult{Cacheable: true, Answer: allAnswers, Authority: finalAuthority, Additional: finalAdditional, Validated: allValidated, ECS: finalECSResponse, Server: usedServer, Hijack: hijackOccurred}
}
