package resolver

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/database"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pending"
	"zjdns/internal/pool"
	"zjdns/server/defense"
	"zjdns/server/resolver/dnssec"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Recursive performs iterative DNS resolution by walking the root, TLD, and
// authoritative nameserver hierarchy. When DNSSEC validation is enabled, it
// builds a cryptographic chain of trust at each delegation step.
//
// Both root servers and per-nameserver addresses share the same latency-sorted
// cache mechanism: per-type TypeA/TypeAAAA entries + ip_latency table. The
// client-facing A/AAAA answers are reordered fastest-first by the cache at
// Get() time (cache.sortAnswerByLatency); the NS addresses below are ordered
// by the resolver's own sortAddrsByLatency.
type Recursive struct {
	resolver    *Resolver
	cache       cache.Store
	db          *database.DB    // delegation cache (zone → NS names + DS); nil in tests
	ctx         context.Context // lifecycle context for background probes
	spoofguard  bool            // from protocol=recursive upstream
	splitguard  bool            // from protocol=recursive upstream
	poisonguard bool            // from protocol=recursive upstream
	hopguard    bool            // from protocol=recursive upstream

	// rootCache memoizes getRootServers' result: the root set changes at
	// most monthly, but the uncached path issues 13 names × 2 types = 26
	// SQLite lookups per recursive query.
	rootCacheMu   sync.Mutex
	rootCache     []string
	rootCacheTime int64 // log.NowUnix() of the cache fill

	// walkGroup coalesces concurrent walks for subdomains of the same zone:
	// while the leader walks a fresh zone (root→TLD→authoritative, populating
	// the delegation cache), followers with the same walkDedupKey wait, then
	// start their own walk from the now-cached zone.  nil in tests.
	walkGroup *pending.ResultGroup[string, QueryResult]

	// dnskeyGroup coalesces DNSKEY fetches per zone — concurrent walks of
	// DIFFERENT zones still fetch the same parent DNSKEYs (e.g. the TLD's).
	// nil in tests.
	dnskeyGroup *pending.ResultGroup[string, struct{}]

	// addrGroup coalesces NS A/AAAA address resolution per nameserver —
	// concurrent walks for different zones that share the same NS name
	// (e.g. a registrar's shared DNS service) each used to perform a full
	// recursive walk from root.  nil in tests.
	addrGroup *pending.ResultGroup[string, QueryResult]
}

// CNAME handles CNAME record chasing during DNS resolution, following the
// redirection chain up to config.DefaultMaxCNAMEChain hops. Defined in the same
// file as Recursive because CNAME resolution depends directly on recursive
// resolution (c.resolve → r.resolve). Splitting into a separate file would
// add unnecessary indirection without reducing coupling.
type CNAME struct {
	resolver *Resolver
}

// walkDedupKey returns the dedup key for a recursive walk: the qname's
// second-level domain (last two labels).  Concurrent queries for different
// subdomains of the same zone share one walk until the delegation cache is
// populated; queries for distinct zones never share one.  The full qname is
// never used as the key — identical queries are already merged by
// handler.PendingRequests before reaching the resolver.
func walkDedupKey(qname string) string {
	fq := dnsutil.Fqdn(qname)
	if fq == "." {
		return fq
	}
	labels := strings.Split(fq[:len(fq)-1], ".")
	if len(labels) <= 2 {
		return fq
	}
	return strings.Join(labels[len(labels)-2:], ".") + "."
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

// dnssecChain tracks the cryptographic trust chain state during recursive
// resolution. At each delegation level, verified parent DNSKEYs and child DS
// records are used to authenticate the child zone's DNSKEYs.
// resolve walks the root→TLD→authoritative hierarchy for a single question.
// The variadic mqt carries an RFC 10029 MQTYPE-Query list of additional
// QTYPEs bundled into every authority query of the walk — the intermediate
// (referral) levels ignore or omit them (§3.4 flag match), the terminal
// authoritative query merges the extra types into one response.  Callers
// without a bundle pass nothing (pre-MQTYPE behaviour).
func (r *Recursive) resolve(ctx context.Context, question Question, ecs *edns.ECSOption, depth int, forceTCP bool, mqt ...[]uint16) QueryResult {
	if depth > config.DefaultMaxRecursionDepth {
		log.Debugf("RECURSION: depth exceeded (depth=%d, max=%d) for %s", depth, config.DefaultMaxRecursionDepth, question.Name)
		return QueryResult{Cacheable: true, Err: fmt.Errorf("recursion depth exceeded: %d", depth)}
	}

	var mqtTypes []uint16
	if len(mqt) > 0 {
		mqtTypes = mqt[0]
	}

	qname := dnsutil.Fqdn(question.Name)
	question.Name = qname
	nameservers := r.getRootServers()
	currentDomain := "."
	normalizedQname := dnsutil.Canonical(qname)

	// poisonSeen is set to true when any VerdictPoisoned is observed at any
	// delegation level, including through internal TCP restarts.  The CNAME
	// resolver uses this to force TCP for subsequent CNAME targets.
	var poisonSeen bool

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

	// Delegation cache: if a cached zone cut exists for an ancestor of the
	// qname, start the walk from the deepest fresh zone instead of the root.
	if record, ok := r.lookupDelegation(qname, question.Qtype); ok {
		if err := r.applyDelegationStart(&nameservers, &currentDomain, &tldServers, chain, record); err == nil {
			minimiseSteps = 0 // restart minimisation schedule from new zone
			log.Debugf("RECURSION: delegation cache hit for %s — starting walk at zone=%s", question.Name, currentDomain)
		}
	}

	// Root-domain query (normalizedQname is empty for the root zone ".").
	if normalizedQname == "." {
		response, verdict, err := r.queryNameserversConcurrent(ctx, nameservers, question, mqtTypes, ecs, forceTCP, currentDomain, r.resolver.validator.Poisonguard)
		if verdict == defense.VerdictPoisoned {
			poisonSeen = true
			// A successful-but-poisoned UDP response for the root zone must
			// restart over TCP like any other level — the main loop handles
			// VerdictPoisoned regardless of err, this branch only handled
			// the err != nil case and served/cached the poisoned answer.
			if !forceTCP {
				if response != nil {
					pool.DefaultMessage.Put(response)
				}
				qr := r.resolve(ctx, question, ecs, depth, true, mqtTypes)
				qr.Poisoned = true
				return qr
			}
		}
		if err != nil {
			if verdict == defense.VerdictPoisoned && !forceTCP {
				log.Debugf("RECURSION: poisonguard triggered TCP fallback for %s (zone=.)", question.Name)
				qr := r.resolve(ctx, question, ecs, depth, true, mqtTypes)
				qr.Poisoned = true
				return qr
			}
			return QueryResult{Cacheable: true, Poisoned: poisonSeen, Err: fmt.Errorf("root domain query: %w", err)}
		}
		cryptoValidated := r.isValidWithDNSSEC(response, currentDomain, chain)
		ecsResponse := r.resolver.edns.ParseFromDNS(response)
		rcode := response.Rcode
		truncated := response.Truncated
		answer, authority, additional := response.Answer, response.Ns, response.Extra
		pool.DefaultMessage.Put(response)
		return QueryResult{Cacheable: true, Answer: answer, Authority: authority, Additional: additional, Rcode: rcode, Validated: cryptoValidated, ECS: ecsResponse, Server: config.ProtoRecursive, Poisoned: poisonSeen, DNSSECEDE: chain.lastEDECode, Truncated: truncated}
	}

	for {
		select {
		case <-ctx.Done():
			return QueryResult{Cacheable: true, Poisoned: poisonSeen, Err: ctx.Err()}
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
			authoritativeForceTCP = r.probeTLDForPoison(ctx, tldServers, qname)
		}

		response, verdict, err := r.queryNameserversConcurrent(ctx, nameservers, queryQuestion, mqtTypes, ecs, authoritativeForceTCP, currentDomain, r.resolver.validator.Poisonguard)

		// ── Single TCP fallback decision point ──────────────────────
		// If any response at this delegation level was flagged as
		// hijack, restart the ENTIRE resolution via TCP.  GFW cannot
		// inject TCP responses, so all subsequent levels (including
		// authoritative) are protected.
		if verdict == defense.VerdictPoisoned {
			poisonSeen = true
			if !forceTCP {
				log.Debugf("RECURSION: poisonguard triggered TCP fallback for %s (zone=%s)", question.Name, currentDomain)
				if response != nil {
					pool.DefaultMessage.Put(response)
				}
				qr := r.resolve(ctx, question, ecs, depth, true, mqtTypes)
				qr.Poisoned = true
				return qr
			}
		}

		if err != nil {
			return QueryResult{Cacheable: true, Poisoned: poisonSeen, Err: fmt.Errorf("query %s: %w", currentDomain, err)}
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

		// RFC 9156 §2.3: when a minimised name returns NXDOMAIN,
		// the intermediate label is not a delegation point.
		// Jump to the full QNAME to avoid querying every
		// non-existent label individually (performance trade-off:
		// §2.3 permits exposing multiple labels per iteration).
		if qnameMinimise && !strings.EqualFold(queryQuestion.Name, qname) && response.Rcode == dns.RcodeNameError {
			pool.DefaultMessage.Put(response)
			minimiseSteps = config.DefaultQnameMinimiseCount
			continue
		}

		if termRes := r.processAnswerWithDNSSEC(ctx, response, nameservers, question, currentDomain, ecs, forceTCP, chain, &validated, ecsResponse); termRes != nil {
			return *termRes
		}

		validated = r.validateNODATAWithNSEC(response, ctx, nameservers, currentDomain, chain, validated)

		// RFC 9824 §5.1: a cryptographically valid compact NODATA proof
		// (NSEC/NSEC3 carrying the NXNAME bit) signals a nonexistent name —
		// restore the NXDOMAIN semantic for the client, the negative cache
		// and the minimisation logic below.
		if validated && dnssec.HasCompactNXNAME(response) {
			log.Debugf("RECURSION: compact NODATA with NXNAME signal for %s — restoring NXDOMAIN", currentDomain)
			response.Rcode = dns.RcodeNameError
		}

		// An authoritative NODATA whose SOA owner is the minimised qname
		// proves the qname is a zone apex — a parent server that also hosts
		// the child zone answered from its child-zone copy instead of
		// referring (RFC 1034 §4.3.2; e.g. CNNIC's cn/com.cn platform).
		// Advance the walk through the zone cut below instead of skipping
		// it — skipping breaks DNSSEC: the no-DS denial for names below the
		// cut is signed by the skipped zone's DNSKEY, which the chain never
		// verified.
		apexCut := qnameMinimise && !strings.EqualFold(queryQuestion.Name, qname) &&
			isApexSOANODATA(response, queryQuestion.Name)

		bestMatch, bestNSRecords, cont, termRes := r.collectBestNSMatch(response, normalizedQname, queryQuestion.Name, qname, qnameMinimise, validated, ecsResponse)
		if termRes != nil {
			return *termRes
		}
		if cont {
			if apexCut {
				if nextNS, nextZone, ok := r.advanceApexZoneCut(ctx, queryQuestion.Name, nameservers, currentDomain, ecs, chain, depth, authoritativeForceTCP, qname); ok {
					if dnsutil.Labels(dnsutil.Fqdn(nextZone)) == 1 {
						tldServers = nextNS
					}
					nameservers = nextNS
					currentDomain = nextZone
					continue
				}
				// The zone cut could not be established (NS query failed, no
				// NS records, or no reachable addresses). Force the full
				// QNAME for the next iteration so the walk leaves the
				// apexCut branch instead of re-issuing the same minimised
				// query until minimiseSteps exhausts (M7).
				minimiseSteps = config.DefaultQnameMinimiseCount
			}
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
			pool.DefaultMessage.Put(response)
			return QueryResult{Cacheable: true, Poisoned: poisonSeen, Err: fmt.Errorf("could not resolve nameservers for %s", bestMatch)}
		}

		r.cacheGlueRecords(nsResult.glue)
		r.storeDelegation(currentDomain, parentDomain, bestNSRecords, nsResult.addrs, chain, verdict)

		pool.DefaultMessage.Put(response)
		nameservers = nsResult.addrs
		// Save TLD servers after updating. Used for the
		// full-QNAME hijack probe at the authoritative step.
		if dnsutil.Labels(dnsutil.Fqdn(currentDomain)) == 1 {
			tldServers = nameservers
		}
	}
}

// probeTLDForPoison sends a single UDP probe to a TLD server for the full
// QNAME and delegates the verdict to security.Detector.IsPoisonedByTLD.
func (r *Recursive) probeTLDForPoison(ctx context.Context, tldServers []string, qname string) bool {
	if !r.poisonguard || len(tldServers) == 0 {
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

	probeCtx, probeCancel := context.WithTimeout(ctx, config.DefaultPoisonProbeTimeout)
	defer probeCancel()

	result := r.resolver.queryClient.ExecuteQuery(probeCtx, msg, server)
	if result.Error != nil || result.Response == nil {
		return false
	}
	defer pool.DefaultMessage.Put(result.Response)

	if r.resolver.validator.Poisonguard.IsPoisonedByTLD(result.Response, qname) {
		log.Debugf("RECURSION: poison probe detected A/AAAA for %s from TLD server %s, forcing TCP",
			qname, tldServers[0])
		return true
	}
	return false
}

func (c *CNAME) resolve(ctx context.Context, question Question, ecs *edns.ECSOption) QueryResult {
	// Walk dedup: concurrent queries for different subdomains of the same
	// zone each used to walk root→TLD→authoritative independently, issuing
	// duplicate NS/DS/DNSKEY queries to the same authorities.  The leader
	// walks and populates the delegation cache; followers wait (bounded by
	// their own ctx), then resolve — their walk starts from the cached zone.
	// Internal resolutions (CNAME targets, NS addresses, TCP restarts) call
	// recursive.resolve directly and bypass this group, so no key is ever
	// re-entered by the same goroutine (self-deadlock impossible).
	if g := c.resolver.recursive.walkGroup; g != nil {
		key := walkDedupKey(question.Name)
		v, _, leader := g.Do(ctx, key, func() (QueryResult, error) {
			return c.resolveInner(ctx, question, ecs), nil
		})
		if leader {
			return v
		}
		// Follower: the leader's walk populated the delegation cache for this
		// zone (or failed — then the cache miss is re-checked and the walk
		// starts from root as before).  Resolve normally.
		return c.resolveInner(ctx, question, ecs)
	}
	return c.resolveInner(ctx, question, ecs)
}

// resolveInner performs the actual CNAME-chain resolution.  Called by
// resolve() under the walk dedup group, and directly by internal paths that
// must not join the group (see resolve).
func (c *CNAME) resolveInner(ctx context.Context, question Question, ecs *edns.ECSOption) QueryResult {
	var allAnswers []dns.RR
	var finalAuthority, finalAdditional []dns.RR
	var finalECSResponse *edns.ECSOption
	var usedServer string
	var poisonOccurred bool
	allValidated := true
	var finalRcode uint16
	var allDNSSECEDE uint16

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

		currentName := dnsutil.Canonical(currentQuestion.Name)
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
					allAnswers = append(allAnswers, rr)
				}
				continue
			}
			if strings.EqualFold(h.Name, currentQuestion.Name) || dns.RRToType(rr) == question.Qtype {
				allAnswers = append(allAnswers, rr)
			}
		}
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
		log.Debugf("RECURSION: CNAME chain exhausted (max=%d) for %s", config.DefaultMaxCNAMEChain, dnsutil.Canonical(question.Name))
	}
	return QueryResult{Cacheable: true, Answer: allAnswers, Authority: finalAuthority, Additional: finalAdditional, Rcode: finalRcode, Validated: allValidated, ECS: finalECSResponse, Server: usedServer, Poisoned: poisonOccurred, DNSSECEDE: allDNSSECEDE}
}
