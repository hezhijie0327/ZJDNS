package resolver

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/defense"
	"zjdns/server/resolver/probe"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/sync/errgroup"
)

// responseEchoesQuestion verifies that a response echoes the query's question
// section (RFC 5452 §9.3).  Without this check, an on-path attacker could
// replay a captured signed response for ANY name in the same zone: the DNSSEC
// signatures cover the RRset, not the question, so the replayed data would
// validate and poison the cache under a different name.
func responseEchoesQuestion(resp *dns.Msg, question Question) bool {
	if resp == nil || len(resp.Question) == 0 {
		return false
	}
	q := resp.Question[0]
	return dns.EqualName(q.Header().Name, question.Name) &&
		dns.RRToType(q) == question.Qtype &&
		q.Header().Class == question.Qclass
}

func (r *Recursive) queryNameserversConcurrent(ctx context.Context, nameservers []string, question Question, ecs *edns.ECSOption, forceTCP bool, currentDomain string, detector defense.Detector) (*dns.Msg, defense.Verdict, error) {
	if len(nameservers) == 0 {
		return nil, defense.VerdictClean, errors.New("no nameservers")
	}

	deadlineCtx, deadlineCancel := context.WithTimeout(ctx, config.DefaultDNSQueryTimeout)
	defer deadlineCancel()
	queryCtx, cancel := context.WithCancel(deadlineCtx)
	defer cancel()

	resultChan := make(chan *dns.Msg, 1)
	g, queryCtx := errgroup.WithContext(queryCtx)
	limit := min(len(nameservers), config.DefaultMaxConcurrentNS)
	g.SetLimit(limit)

	var poisonRejected atomic.Bool
	var nxdomainMsg atomic.Pointer[dns.Msg] // NXDOMAIN stored as secondary — never wins race against NOERROR
	normalizedQname := dnsutil.Canonical(question.Name)

	baseMsg := r.resolver.buildMsg(question, ecs, false, false)
	baseMsg.UDPSize = pool.RecursiveUDPBufferSize
	for _, ns := range nameservers {
		nsAddr := ns
		protocol := config.ProtoUDP
		if forceTCP {
			protocol = config.ProtoTCP
		}
		server := &config.UpstreamServer{
			Address:    nsAddr,
			Protocol:   protocol,
			Proxy:      r.resolver.recursiveProxyURL,
			Spoofguard: r.spoofguard && protocol == config.ProtoUDP,
			Splitguard: r.splitguard && protocol == config.ProtoTCP,
			HopGuard:   r.hopguard && protocol == config.ProtoUDP,
		}

		g.Go(func() error {
			defer zdnsutil.HandlePanic("Query nameserver")

			select {
			case <-queryCtx.Done():
				return queryCtx.Err()
			default:
			}

			msg := pool.DefaultMessage.Get()
			defer pool.DefaultMessage.Put(msg)
			if len(baseMsg.Question) > 0 {
				msg.Question = append(msg.Question, baseMsg.Question[0])
			}
			msg.RecursionDesired = baseMsg.RecursionDesired
			msg.CheckingDisabled = baseMsg.CheckingDisabled
			msg.Security = baseMsg.Security
			msg.UDPSize = baseMsg.UDPSize
			// EDNS(0) options (ECS SUBNET, cookie, padding) live in Pseudo in
			// this fork — without this copy the caller's explicit ECS never
			// reached the authoritative servers (geo-aware resolution broke).
			msg.Pseudo = append(msg.Pseudo, baseMsg.Pseudo...)
			// ExecuteQuery reads msg via Pack()/Data — caller retains ownership.

			subCtx, subCancel := context.WithTimeout(queryCtx, config.DefaultDNSQueryTimeout)
			defer subCancel()

			result := r.resolver.queryClient.ExecuteQuery(subCtx, msg, server)
			if result.Error == nil && result.Response != nil {
				// RFC 5452 §9.3: reject responses that do not echo the query's
				// question — a replayed signed response for a different name
				// in the same zone would otherwise validate and poison the
				// cache (R3-H1).
				if !responseEchoesQuestion(result.Response, question) {
					log.Debugf("RECURSION: ns=%s question echo mismatch for %s %s", nsAddr, question.Name, dns.TypeToString[question.Qtype])
					pool.DefaultMessage.Put(result.Response)
					return nil
				}
				rcode := result.Response.Rcode

				if rcode == dns.RcodeNameError && len(result.Response.Answer) > 0 && !result.Response.Authoritative {
					// RFC 6604 §3: NXDOMAIN may include CNAME/DNAME records
					// when the original query name is an alias whose target
					// does not exist. Only reject when non-alias answer records
					// are present — those indicate data injection.
					//
					// Note: this check only triggers when the AA flag is absent.
					// GFW-injected responses can carry fake AA=1, so this gate
					// alone is insufficient. NXDOMAIN deferral (below) provides
					// the primary defence: fake NXDOMAIN never wins the race
					// against a real NOERROR response.
					hasNonAlias := false
					for _, rr := range result.Response.Answer {
						switch rr.(type) {
						case *dns.CNAME, *dns.DNAME:
						default:
							hasNonAlias = true
						}
					}
					if hasNonAlias {
						log.Debugf("RECURSION: rejecting malformed NXDOMAIN+answer — poison from %s", nsAddr)
						poisonRejected.Store(true)
						pool.DefaultMessage.Put(result.Response)
						return nil
					}
				}
				if rcode == dns.RcodeSuccess {
					// Reject truncated responses: a TC bit over TCP means
					// the authoritative server could not deliver a complete
					// answer even over a stream transport (RFC 1035 §4.2.2).
					if result.Response.Truncated {
						log.Debugf("RECURSION: ns=%s truncated response for %s %s — skipping", nsAddr, question.Name, dns.TypeToString[question.Qtype])
						pool.DefaultMessage.Put(result.Response)
						return nil
					}
					if r.poisonguard {
						v := detector.Validate(currentDomain, normalizedQname, result.Response)
						if v == defense.VerdictPoisoned {
							log.Debugf("RECURSION: rejecting poisoned response from %s", nsAddr)
							poisonRejected.Store(true)
							pool.DefaultMessage.Put(result.Response)
							return nil
						}
					}

					select {
					case resultChan <- result.Response:
						cancel()
						return nil
					case <-queryCtx.Done():
						pool.DefaultMessage.Put(result.Response)
						return queryCtx.Err()
					}
				}

				if rcode == dns.RcodeNameError {
					// NXDOMAIN is deferred — GFW can inject fake NXDOMAIN
					// faster than real NOERROR responses. By storing it as
					// a secondary result (never canceling the errgroup), we
					// give legitimate NOERROR responses time to arrive.
					// Falls back to NXDOMAIN only if no NOERROR succeeds.
					if r.poisonguard {
						v := detector.Validate(currentDomain, normalizedQname, result.Response)
						if v == defense.VerdictPoisoned {
							log.Debugf("RECURSION: rejecting poisoned response from %s", nsAddr)
							poisonRejected.Store(true)
							pool.DefaultMessage.Put(result.Response)
							return nil
						}
					}

					if !nxdomainMsg.CompareAndSwap(nil, result.Response) {
						pool.DefaultMessage.Put(result.Response)
					}
					return nil
				}

				if rcode == dns.RcodeFormatError {
					pool.DefaultMessage.Put(result.Response)
					r.retryWithoutEDNS(queryCtx, resultChan, cancel, server, question, nsAddr, detector, currentDomain, normalizedQname, &poisonRejected)
					return nil
				}

				log.Debugf("RECURSION: ns=%s rcode=%s for %s %s", nsAddr, dns.RcodeToString[rcode], question.Name, dns.TypeToString[question.Qtype])
				pool.DefaultMessage.Put(result.Response)
			} else if result.Error != nil {
				log.Debugf("RECURSION: ns=%s error=%v for %s %s", nsAddr, result.Error, question.Name, dns.TypeToString[question.Qtype])
			}
			return nil
		})
	}

	// Wait for first successful response, or until all goroutines complete.
	// This ensures every nameserver gets a fair chance — when some
	// addresses fail instantly (e.g. IPv6 unreachable on an IPv4-only host),
	// we don't prematurely time out before the remaining addresses have been
	// tried. With spoofguard, goroutines internally collect for up to 500ms
	// before sending a result, so the errgroup naturally accounts for that.
	errgroupDone := make(chan struct{})
	go func() {
		defer zdnsutil.HandlePanic("Query nameservers wait")
		defer close(errgroupDone)
		if err := g.Wait(); err != nil {
			log.Debugf("RECURSION: NS query errgroup: %v", err)
		}
		// baseMsg is read by every worker (including those still queued
		// behind SetLimit when the caller returned early on the first
		// response) — returning it here, after g.Wait, guarantees no
		// worker reads a pooled message that was already zeroed or
		// reused by another query.
		pool.DefaultMessage.Put(baseMsg)
	}()

	verdict := defense.VerdictClean

	select {
	case resp := <-resultChan:
		if nx := nxdomainMsg.Load(); nx != nil {
			pool.DefaultMessage.Put(nx)
		}
		if poisonRejected.Load() {
			verdict = defense.VerdictPoisoned
		}
		return resp, verdict, nil
	case <-errgroupDone:
	case <-ctx.Done():
	}

	// Drain a NOERROR result that arrived concurrently with errgroupDone or
	// ctx cancellation: both select cases can be ready at once (Go picks
	// uniformly), and dropping the buffered response here would fall through
	// to the NXDOMAIN fallback with a wrong answer.
	select {
	case resp := <-resultChan:
		if nx := nxdomainMsg.Load(); nx != nil {
			pool.DefaultMessage.Put(nx)
		}
		if poisonRejected.Load() {
			verdict = defense.VerdictPoisoned
		}
		return resp, verdict, nil
	default:
	}

	// No NOERROR response — fall back to NXDOMAIN if one was collected.
	if nx := nxdomainMsg.Load(); nx != nil {
		if poisonRejected.Load() {
			verdict = defense.VerdictPoisoned
		}
		return nx, verdict, nil
	}

	if poisonRejected.Load() {
		verdict = defense.VerdictPoisoned
	}
	log.Debugf("RECURSION: all %d nameservers failed for %s (zone=%s)", len(nameservers), question.Name, currentDomain)
	return nil, verdict, errors.New("no successful response")
}

func (r *Recursive) resolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS, qname string, depth int, forceTCP bool) []string {
	if len(nsRecords) == 0 {
		return nil
	}

	// Resolve NS addresses concurrently, then shuffle so the
	// concurrency-limited first batch is not biased toward the
	// delegation order. Latency-probed order is restored on
	// subsequent queries via the cache.

	resolveCtx, resolveCancel := context.WithTimeout(ctx, config.DefaultDNSQueryTimeout)
	defer resolveCancel()

	g, queryCtx := errgroup.WithContext(resolveCtx)
	g.SetLimit(concurrencyLimit(len(nsRecords)))

	var allMu sync.Mutex
	var allAddresses []string

	// Accumulate resolved A/AAAA records per NS name so they can be
	// latency-probed and re-cached asynchronously — matching the glue
	// record path in resolve().
	var nsRecordsMu sync.Mutex
	var aRecordsMap map[string][]dns.RR
	var aaaaRecordsMap map[string][]dns.RR

	for _, ns := range nsRecords {
		nsRecord := ns
		g.Go(func() error {
			defer zdnsutil.HandlePanic("Resolve NS addresses")
			select {
			case <-queryCtx.Done():
				return nil
			default:
			}

			if domainNamesEqual(nsRecord.Ns, qname) {
				return nil
			}

			nsName := dnsutil.Fqdn(nsRecord.Ns)

			// Try cache first — records may already be latency-probed.
			cachedAddrs := r.lookupNSAddrsFromCache(nsName, nil)
			if len(cachedAddrs) > 0 {
				allMu.Lock()
				allAddresses = append(allAddresses, cachedAddrs...)
				allMu.Unlock()
				return nil
			}

			// Cache miss: resolve A and AAAA concurrently.  The A walk
			// bundles AAAA via RFC 10029 (one authority query instead of
			// two walks); when the authority merges AAAA into the A
			// response, the AAAA walk short-circuits.
			var nsAddrs []string
			var ansARecords []dns.RR
			var ansAAAARecords []dns.RR
			var addrMu sync.Mutex
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer zdnsutil.HandlePanic("Resolve NS A")
				defer wg.Done()
				if queryCtx.Err() != nil {
					return
				}
				ansARecords = r.resolveNSAddrType(queryCtx, nsName, dns.TypeA, depth+1, forceTCP, &nsAddrs, &addrMu)
			}()

			go func() {
				defer zdnsutil.HandlePanic("Resolve NS AAAA")
				defer wg.Done()
				if queryCtx.Err() != nil {
					return
				}
				ansAAAARecords = r.resolveNSAddrType(queryCtx, nsName, dns.TypeAAAA, depth+1, forceTCP, &nsAddrs, &addrMu)
			}()

			wg.Wait()

			// A concurrently started AAAA walk may have added addresses the
			// merged A response also carries — deduplicate before use.
			seenAddrs := make(map[string]struct{}, len(nsAddrs))
			uniqAddrs := nsAddrs[:0]
			for _, addr := range nsAddrs {
				if _, ok := seenAddrs[addr]; ok {
					continue
				}
				seenAddrs[addr] = struct{}{}
				uniqAddrs = append(uniqAddrs, addr)
			}
			nsAddrs = uniqAddrs

			if len(nsAddrs) == 0 {
				return nil
			}

			// Cache A/AAAA records so future queries hit warm cache.
			// The async latency probe below reorders them later for
			// latency-optimized cache hits.
			if r.cache != nil && len(ansARecords) > 0 {
				r.cache.Set(nsName, dns.TypeA, dns.ClassINET, nil, false, ansARecords, nil, nil, false, 0)
			}
			if r.cache != nil && len(ansAAAARecords) > 0 {
				r.cache.Set(nsName, dns.TypeAAAA, dns.ClassINET, nil, false, ansAAAARecords, nil, nil, false, 0)
			}

			// Accumulate records for async latency probe.
			if r.cache != nil && (len(ansARecords) > 0 || len(ansAAAARecords) > 0) {
				nsRecordsMu.Lock()
				if aRecordsMap == nil {
					aRecordsMap = make(map[string][]dns.RR)
					aaaaRecordsMap = make(map[string][]dns.RR)
				}
				if len(ansARecords) > 0 {
					aRecordsMap[nsName] = append(aRecordsMap[nsName], ansARecords...)
				}
				if len(ansAAAARecords) > 0 {
					aaaaRecordsMap[nsName] = append(aaaaRecordsMap[nsName], ansAAAARecords...)
				}
				nsRecordsMu.Unlock()
			}

			allMu.Lock()
			allAddresses = append(allAddresses, nsAddrs...)
			allMu.Unlock()
			return nil
		})
	}

	_ = g.Wait() // _ = error: NS fan-out is best-effort — individual failures logged inside

	// Fire background latency probes. Merge A+AAAA per NS name
	// so each probe call gets both address families.
	if r.cache != nil && (len(aRecordsMap) > 0 || len(aaaaRecordsMap) > 0) {
		combined := make(map[string][]string)
		for nsName, records := range aRecordsMap {
			combined[nsName] = addrsFromRRs(records)
		}
		for nsName, records := range aaaaRecordsMap {
			combined[nsName] = append(combined[nsName], addrsFromRRs(records)...)
		}
		for _, addrs := range combined {
			if probe.TryProbeNSAddrs(r.cache, addrs) {
				go func() { defer zdnsutil.HandlePanic("NS addr probe"); probe.ProbeNSAddrs(r.ctx, r.cache, addrs) }()
			}
		}
	}

	allMu.Lock()
	// Global dedup: the same IP reached via different NS names (common with
	// registrar shared DNS) was queried once per NS name — one query per
	// unique address is enough (M-low).
	seen := make(map[string]struct{}, len(allAddresses))
	uniq := allAddresses[:0]
	for _, addr := range allAddresses {
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		uniq = append(uniq, addr)
	}
	ShuffleSlice(uniq)
	allMu.Unlock()
	return uniq
}

// domainNamesEqual compares two strings case-insensitively, ignoring a single
// trailing dot on either string. Uses sub-slicing (no allocation) instead of
// strings.TrimSuffix (which allocates when the suffix is present).
func domainNamesEqual(a, b string) bool {
	if a != "" && a[len(a)-1] == '.' {
		a = a[:len(a)-1]
	}
	if b != "" && b[len(b)-1] == '.' {
		b = b[:len(b)-1]
	}
	return strings.EqualFold(a, b)
}

// retryWithoutEDNS attempts a query without EDNS options and sends the result
// to resultChan. Used as a FORMERR fallback per RFC 6891 §6.2.2.
func (r *Recursive) retryWithoutEDNS(ctx context.Context, resultChan chan<- *dns.Msg, cancel context.CancelFunc, server *config.UpstreamServer, question Question, nsAddr string, detector defense.Detector, currentDomain, normalizedQname string, poisonRejected *atomic.Bool) {
	log.Debugf("RECURSION: ns=%s FORMERR, retrying without EDNS for %s %s", nsAddr, question.Name, dns.TypeToString[question.Qtype])

	bareMsg := pool.DefaultMessage.Get()
	defer pool.DefaultMessage.Put(bareMsg)
	dnsutil.SetQuestion(bareMsg, dnsutil.Fqdn(question.Name), question.Qtype)
	bareMsg.RecursionDesired = false

	retryCtx, retryCancel := context.WithTimeout(ctx, config.DefaultDNSQueryTimeout)
	defer retryCancel()
	retryResult := r.resolver.queryClient.ExecuteQuery(retryCtx, bareMsg, server)

	if retryResult.Error != nil {
		log.Debugf("RECURSION: ns=%s FORMERR retry error=%v for %s %s", nsAddr, retryResult.Error, question.Name, dns.TypeToString[question.Qtype])
		return
	}
	if retryResult.Response == nil {
		return
	}
	// RFC 5452 §9.3: same question-echo gate as the main path (R3-H1).
	if !responseEchoesQuestion(retryResult.Response, question) {
		log.Debugf("RECURSION: ns=%s FORMERR retry question echo mismatch for %s %s", nsAddr, question.Name, dns.TypeToString[question.Qtype])
		pool.DefaultMessage.Put(retryResult.Response)
		return
	}

	retryRcode := retryResult.Response.Rcode
	if retryRcode != dns.RcodeSuccess && retryRcode != dns.RcodeNameError {
		log.Debugf("RECURSION: ns=%s FORMERR retry rcode=%s for %s %s", nsAddr, dns.RcodeToString[retryRcode], question.Name, dns.TypeToString[question.Qtype])
		pool.DefaultMessage.Put(retryResult.Response)
		return
	}

	// Reject hijacked responses in FORMERR retry path as well.
	if r.poisonguard {
		v := detector.Validate(currentDomain, normalizedQname, retryResult.Response)
		if v == defense.VerdictPoisoned {
			log.Debugf("RECURSION: rejecting poisoned FORMERR retry from %s", nsAddr)
			poisonRejected.Store(true)
			pool.DefaultMessage.Put(retryResult.Response)
			return
		}
	}

	select {
	case resultChan <- retryResult.Response:
		cancel()
	case <-ctx.Done():
		pool.DefaultMessage.Put(retryResult.Response)
	}
}

// resolveNSAddrType resolves a single NS address type (A or AAAA) and appends
// resolved addresses to nsAddrs under addrMu. For A queries, AAAA glue from
// the Additional section is also collected.
func (r *Recursive) resolveNSAddrType(ctx context.Context, nsName string, qtype uint16, depth int, forceTCP bool, nsAddrs *[]string, addrMu *sync.Mutex) (answer []dns.RR) {
	var qr QueryResult
	if r.addrGroup != nil {
		// Dedup the full recursive walk per NS name + qtype: concurrent
		// walks for different zones that share the same NS name (e.g. a
		// registrar's shared DNS) each used to walk root→TLD→auth for it.
		key := nsName + "/" + dns.TypeToString[qtype]
		qr, _, _ = r.addrGroup.Do(ctx, key, func(workCtx context.Context) (QueryResult, error) { // _ = verdict, _ = error: dedup follower — leader result already gated
			return r.resolve(workCtx, Question{Name: nsName, Qtype: qtype, Qclass: dns.ClassINET}, nil, depth, forceTCP), nil
		})
	} else {
		qr = r.resolve(ctx, Question{Name: nsName, Qtype: qtype, Qclass: dns.ClassINET}, nil, depth, forceTCP)
	}
	if qr.Err != nil {
		return answer
	}
	addrMu.Lock()
	defer addrMu.Unlock()
	for _, rrec := range qr.Answer {
		switch a := rrec.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				*nsAddrs = append(*nsAddrs, net.JoinHostPort(a.A.String(), config.DefaultUDPPort))
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				*nsAddrs = append(*nsAddrs, net.JoinHostPort(a.AAAA.String(), config.DefaultUDPPort))
			}
		}
	}
	// For A queries, also collect AAAA glue from Additional.
	if qtype == dns.TypeA {
		for _, rrec := range qr.Additional {
			if aaaa, ok := rrec.(*dns.AAAA); ok && strings.EqualFold(aaaa.Header().Name, nsName) {
				*nsAddrs = append(*nsAddrs, net.JoinHostPort(aaaa.AAAA.String(), config.DefaultUDPPort))
			}
		}
	}
	return qr.Answer
}
