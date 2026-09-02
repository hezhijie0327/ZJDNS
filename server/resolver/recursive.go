package resolver

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/internal/pending"
	"zjdns/internal/pool"
	"zjdns/internal/spillfile"
	"zjdns/server/defense"
	"zjdns/server/resolver/dnssec"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// pendingChainUpdate is a deferred DNSSEC chain update for a zone cut whose
// referral carried no DS records: the authenticated no-DS proof needs a
// network query to the parent, so the update keeps running in the background
// while the walk proceeds to the child level — the proof overlaps the
// next-level fan-out instead of serializing before it.  Joined (and the
// delegation stored) right after the next query returns, before the chain is
// read again.  The referral response stays owned by the pending update — Put
// only after the join.
type pendingChainUpdate struct {
	done     chan struct{}
	response *dns.Msg // referral response still read by the background update
	zone     string
	parent   string
	nsNames  []*dns.NS
	addrs    []string
	verdict  defense.Verdict
}

// Recursive performs iterative DNS resolution by walking the root, TLD, and
// authoritative nameserver hierarchy. When DNSSEC validation is enabled, it
// builds a cryptographic chain of trust at each delegation step.
//
// Both root servers and per-nameserver addresses share the same latency-sorted
// cache mechanism: per-type TypeA/TypeAAAA entries + per-IP latency map. The
// client-facing A/AAAA answers are reordered fastest-first by the cache at
// Get() time (cache.sortAnswerByLatency); the NS addresses below are ordered
// by the resolver's own sortAddrsByLatency.
type Recursive struct {
	resolver    *Resolver
	cache       cache.Store
	ctx         context.Context                       // lifecycle context for background probes
	delegations *lrumap.Map[string, *delegationEntry] // zone-cut delegation cache (zone → NS names + DS)

	// spill is the delegation disk tier: evicted-but-fresh delegations land
	// here and are promoted back on a lookup miss.  nil when no state_file
	// is configured.
	spill    *spillfile.Store
	spillCap int // spill record cap (≤0 = unbounded)

	// spillW drains delegation eviction writes off the delegations mutex
	// (2026-09 D2/R1 — OnEvict ran a synchronous WriteAt under the lock
	// that guards every lookupDelegation on the recursive hot path).
	spillW *spillfile.AsyncWriter

	spoofguard  bool     // from protocol=recursive upstream
	splitguard  bool     // from protocol=recursive upstream
	poisonguard bool     // from protocol=recursive upstream
	hopguard    bool     // from protocol=recursive upstream
	capsguard   bool     // from protocol=recursive upstream
	mqtype      []uint16 // RFC 10029 MQTYPE-Query types (from protocol=recursive upstream)
	// addressFamily restricts fan-out to one family ("dual"|"ipv4"|"ipv6",
	// from server.features.address_family — explicit operator choice).
	addressFamily string

	// rootCache memoizes getRootServers' result: the root set changes at
	// most monthly, but the uncached path issues 13 names × 2 types = 26
	// spill-tier lookups per recursive query.
	rootCacheMu   sync.Mutex
	rootCache     []string
	rootCacheTime int64 // log.NowUnix() of the cache fill

	// dnskeyFlight deduplicates concurrent DNSKEY fetches per zone.  The
	// zone-key cache only deduplicates AFTER a fetch succeeds, so a
	// cold-cache burst of concurrent walks previously fired N×len(nameservers)
	// parallel upstream DNSKEY queries — the DNSSEC burst amplifier behind
	// multi-hundred-MB transient heap spikes under load.
	dnskeyFlightOnce sync.Once
	dnskeyFlight     *pending.ResultGroup[string, []*dns.DNSKEY]

	// nsAddrFlight deduplicates concurrent NS-address walks per (name, qtype).
	// When a delegation's NS addresses never resolve (unreachable
	// authoritative servers), every level and every concurrent client query
	// previously respawned the full walk for the same NS names — one lookup
	// amplified into ~290k UDP queries (kernel.org → nsXX.constellix.{com,net}
	// storm, 2026-08).  One leader walks; followers share the result, bounded
	// by their own context.
	nsAddrFlightOnce sync.Once
	nsAddrFlight     *pending.ResultGroup[string, nsAddrFlightResult]

	// inFlightQueries counts recursive fan-out queries currently in flight
	// across all walks.  queryNameserversConcurrent drops new queries above
	// config.DefaultMaxRecursiveInflightQueries — the last-line amplifier
	// guard under the NS-address singleflight.
	inFlightQueries atomic.Int64
}

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

// resolve walks the root→TLD→authoritative hierarchy for a single question.
func (r *Recursive) resolve(ctx context.Context, question Question, ecs *edns.ECSOption, depth int, forceTCP bool) QueryResult {
	if depth > config.DefaultMaxRecursionDepth {
		log.Debugf("RECURSION: depth exceeded (depth=%d, max=%d) for %s", depth, config.DefaultMaxRecursionDepth, question.Name)
		return QueryResult{Cacheable: true, Err: fmt.Errorf("recursion depth exceeded: %d", depth)}
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

	// poisonProbed records that this walk already ran the TLD hijack probe;
	// a positive verdict is persisted in forceTCP, so probing once per walk
	// is sufficient (re-probing the same TLD servers for the same qname at
	// every full-QNAME level only paid their straggler latency again).
	var poisonProbed bool

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
		response, verdict, err := r.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP, currentDomain, r.resolver.validator.Poisonguard)
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
				qr := r.resolve(ctx, question, ecs, depth, true)
				qr.Poisoned = true
				return qr
			}
		}
		if err != nil {
			if verdict == defense.VerdictPoisoned && !forceTCP {
				log.Debugf("RECURSION: poisonguard triggered TCP fallback for %s (zone=.)", question.Name)
				qr := r.resolve(ctx, question, ecs, depth, true)
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

	// pendingChain is a DNSSEC chain update deferred from the previous
	// delegation (no-DS proof running in the background); keyPrefetchDone
	// signals this level's DNSKEY prefetch goroutine.  They never run
	// together: the prefetch only fires once the prior update has been joined.
	// probeDone carries the overlapped TLD hijack-probe verdict (see below).
	var pendingChain *pendingChainUpdate
	var keyPrefetchDone chan struct{}
	var probeDone chan bool

	for {
		select {
		case <-ctx.Done():
			return QueryResult{Cacheable: true, Poisoned: poisonSeen, Err: ctx.Err()}
		default:
		}

		// DNSKEY prefetch: the first signed-zone query at a level otherwise
		// serializes a DNSKEY fetch after the data response arrives
		// (isDNSSECValid → ensureZoneDNSKEYs) — one extra RTT per cold zone.
		// Fire the fetch now so it overlaps this level's fan-out query; the
		// singleflight inside ensureZoneDNSKEYs dedupes concurrent walks.
		// Skipped while a chain update is still pending: it owns chain and
		// determines whether this zone is signed at all.  The root-start case
		// has no childDS yet (no delegation has been seen), but the root zone
		// is always signed and its keys are needed to verify the first
		// delegation — without this branch the walk paid one serial root
		// DNSKEY RTT inside updateDNSSECChain.  Non-root starts keep the
		// childDS requirement: a delegation-cache start on an unsigned zone
		// carries empty DS and would otherwise fire a wasted DNSKEY query.
		if pendingChain == nil && r.resolver.validator.Crypto != nil &&
			len(chain.zoneDNSKEYs) == 0 && !chain.dsPresentButUnverified &&
			(len(chain.childDS) > 0 || currentDomain == config.DNSRootZone) {
			keyPrefetchDone = make(chan struct{})
			go func() {
				defer zdnsutil.HandlePanic("DNSKEY prefetch")
				defer close(keyPrefetchDone)
				r.ensureZoneDNSKEYs(ctx, nameservers, currentDomain, chain)
			}()
		}

		var queryQuestion Question
		queryQuestion, minimiseSteps = r.applyQnameMinimisation(question, qname, currentDomain, qnameMinimise, minimiseSteps)

		// When QNAME minimisation exposes the full QNAME at a
		// non-authoritative zone (root/TLD/intermediate), probe
		// the servers we are about to query.  A legitimate
		// delegation server never returns A/AAAA for a
		// subdomain — if it does, the GFW is injecting at this
		// level.  The probe runs at most once per walk — at the
		// first level exposing the full QNAME (delegation-cache
		// starts probe at the authoritative level instead).
		// The probe overlaps this level's data query instead of
		// serializing before it: the verdict is joined right after
		// the query returns, and a positive verdict discards the
		// (possibly injected) UDP answer and restarts the walk over
		// TCP — the probe hits the same servers as the data query,
		// so an injection that corrupts the answer also corrupts the
		// probe and is detected.
		if !forceTCP && qnameMinimise && !poisonProbed &&
			strings.EqualFold(queryQuestion.Name, qname) &&
			len(tldServers) > 0 {
			poisonProbed = true
			probeDone = make(chan bool, 1)
			go func() {
				defer zdnsutil.HandlePanic("TLD poison probe")
				probeDone <- r.probeTLDForPoison(ctx, tldServers, qname)
			}()
		}

		response, verdict, err := r.queryNameserversConcurrent(ctx, nameservers, queryQuestion, ecs, forceTCP, currentDomain, r.resolver.validator.Poisonguard)

		// Join the level's DNSKEY prefetch before anything touches chain —
		// from here on the main goroutine owns chain again.  The wait is
		// normally zero: the fetch overlapped the fan-out query above.
		if keyPrefetchDone != nil {
			<-keyPrefetchDone
			keyPrefetchDone = nil
		}
		// Join a chain update deferred from the previous delegation (no-DS
		// proof) and store its delegation now — the proof overlapped this
		// level's query instead of serializing before the walk continued.
		if pendingChain != nil {
			<-pendingChain.done
			if len(pendingChain.addrs) > 0 {
				r.storeDelegation(pendingChain.zone, pendingChain.parent, pendingChain.nsNames, pendingChain.addrs, chain, pendingChain.verdict)
			}
			pool.DefaultMessage.Put(pendingChain.response)
			pendingChain = nil
		}

		// Join the overlapped hijack probe before anything reads the
		// response: a positive verdict means this level is injecting,
		// so the UDP answer is dropped and the walk restarts over TCP
		// (same recovery as the per-response VerdictPoisoned path below).
		if probeDone != nil {
			if <-probeDone {
				log.Debugf("RECURSION: poisonguard probe detected injection for %s (zone=%s) — restarting over TCP", question.Name, currentDomain)
				if response != nil {
					pool.DefaultMessage.Put(response)
				}
				qr := r.resolve(ctx, question, ecs, depth, true)
				qr.Poisoned = true
				return qr
			}
			probeDone = nil
		}

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
				qr := r.resolve(ctx, question, ecs, depth, true)
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

		// RFC 10029: warm the merged types and strip them from the
		// client-facing answer — the strip uses the completed list, never
		// r.mqtype, which would remove the primary records.
		if len(r.mqtype) > 0 {
			if mqr, invalid := parseMQResponse(response); mqr != nil && !invalid {
				r.resolver.warmFromMQResponse(response, queryQuestion.Name, queryQuestion.Qclass, mqr, ecsResponse, cryptoValidated)
				response.Answer = stripMQBundled(response.Answer, mqr.Types)
			}
		}

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
				if nextNS, nextZone, ok := r.advanceApexZoneCut(ctx, queryQuestion.Name, nameservers, currentDomain, ecs, chain, depth, forceTCP, qname); ok {
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
		//
		// Save parent zone before updating — glue name validation uses
		// the parent zone (the zone that published the delegation),
		// not the delegated-to zone.
		parentDomain := currentDomain
		currentDomain = bestMatch

		// DNSSEC chain update and the next-level NS address resolution
		// are independent queries against the same (parent) servers —
		// run them concurrently instead of serially (DNSKEY fetch and
		// NS-name resolution each do their own walk).
		//
		// Exception: a referral WITHOUT DS records under enforcement needs an
		// authenticated no-DS proof — a network query to the parent.  That
		// proof is deferred to the background: the walk joins it right after
		// the next level's query returns, so it overlaps the child fan-out
		// instead of serializing when NS addresses resolve instantly from
		// glue/cache.  The DS-present path stays synchronous: it is CPU-only
		// (parent keys were fetched entering this zone) and its childDS feeds
		// the next level's DNSKEY prefetch.
		referralHasDS := len(dnssec.FindDS(response.Ns)) > 0 || len(dnssec.FindDS(response.Answer)) > 0
		var nsResult resolvedNSAddrs
		if !referralHasDS && r.resolver.DNSSECEnforce && r.resolver.validator.Crypto != nil {
			nsDone := make(chan struct{})
			go func() {
				defer zdnsutil.HandlePanic("Resolve NS addresses")
				defer close(nsDone)
				nsResult = r.resolveNextNameservers(ctx, bestNSRecords, response, qname, parentDomain, depth, forceTCP)
			}()
			chainDone := make(chan struct{})
			go func() {
				defer zdnsutil.HandlePanic("DNSSEC chain update")
				defer close(chainDone)
				r.updateDNSSECChain(ctx, response, parentDomain, bestMatch, nameservers, chain)
			}()
			<-nsDone
			pendingChain = &pendingChainUpdate{
				done:     chainDone,
				response: response, // still read by the background update — Put after the join
				zone:     currentDomain,
				parent:   parentDomain,
				nsNames:  bestNSRecords,
				addrs:    nsResult.addrs,
				verdict:  verdict,
			}
		} else {
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer zdnsutil.HandlePanic("DNSSEC chain update")
				defer wg.Done()
				r.updateDNSSECChain(ctx, response, parentDomain, bestMatch, nameservers, chain)
			}()
			go func() {
				defer zdnsutil.HandlePanic("Resolve NS addresses")
				defer wg.Done()
				nsResult = r.resolveNextNameservers(ctx, bestNSRecords, response, qname, parentDomain, depth, forceTCP)
			}()
			wg.Wait()
		}

		if len(nsResult.addrs) > 0 {
			log.Debugf("RECURSION: zone=%s, %d NS names -> %d addresses (source=%s): %v",
				currentDomain, len(bestNSRecords), len(nsResult.addrs), nsResult.source, nsResult.addrs)
		}

		if pendingChain != nil {
			// The background chain update still reads response — ownership
			// moves to pendingChain (Put after the join).  The empty-address
			// failure is reported by the next iteration's query attempt after
			// the join, so the walk fails instead of stalling here.
			r.cacheGlueRecords(nsResult.glue)
			nameservers = nsResult.addrs
			if dnsutil.Labels(dnsutil.Fqdn(currentDomain)) == 1 {
				tldServers = nameservers
			}
			continue
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

// probeTLDForPoison probes the first few TLD servers concurrently for the
// full QNAME and delegates the verdict to security.Detector.IsPoisonedByTLD.
// Any peer's A/AAAA answer is injection evidence (a TLD server never
// legitimately answers a subdomain), so any poisoned verdict forces TCP; the
// concurrent fan-out covers single-server drops that previously stretched the
// probe to its full timeout.
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
			// (old behaviour) surfaced unrelated same-type records from
			// other owners into the chain (M-low).
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
		log.Debugf("RECURSION: CNAME chain exhausted (max=%d) for %s", config.DefaultMaxCNAMEChain, dnsutil.Canonical(question.Name))
	}
	return QueryResult{Cacheable: true, Answer: allAnswers, Authority: finalAuthority, Additional: finalAdditional, Rcode: finalRcode, Validated: allValidated, ECS: finalECSResponse, Server: usedServer, Poisoned: poisonOccurred, DNSSECEDE: allDNSSECEDE, Truncated: truncated}
}
