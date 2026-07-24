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

	var activeConnections atomic.Int32
	var poisonRejected atomic.Bool
	normalizedQname := dnsutil.Canonical(question.Name)

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
		}

		g.Go(func() error {
			defer zdnsutil.HandlePanic("Query nameserver")
			activeConnections.Add(1)
			defer activeConnections.Add(-1)

			select {
			case <-queryCtx.Done():
				return queryCtx.Err()
			default:
			}

			msg := r.resolver.buildMsg(question, ecs, false, false)
			msg.UDPSize = pool.RecursiveUDPBufferSize
			defer pool.DefaultMessage.Put(msg)

			subCtx, subCancel := context.WithTimeout(queryCtx, config.DefaultDNSQueryTimeout)
			defer subCancel()

			result := r.resolver.queryClient.ExecuteQuery(subCtx, msg, server)
			if result.Error == nil && result.Response != nil {
				rcode := result.Response.Rcode

				if rcode == dns.RcodeNameError && len(result.Response.Answer) > 0 && !result.Response.Authoritative {
					// RFC 6604 §1.1: NXDOMAIN may include CNAME/DNAME records
					// when the original query name is an alias whose target
					// does not exist. Only reject when non-alias answer records
					// are present — those indicate data injection.
					//
					// When the AA (Authoritative Answer) flag is set, the
					// response originates from the zone's own nameserver —
					// trust it even if it carries unusual NXDOMAIN+answer
					// records (e.g. Microsoft outlook.com returns NXDOMAIN
					// with placeholder A records for delegated sub-zones).
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
				if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
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
		defer close(errgroupDone)
		if err := g.Wait(); err != nil {
			log.Debugf("RECURSION: NS query errgroup: %v", err)
		}
	}()

	verdict := defense.VerdictClean

	select {
	case resp := <-resultChan:
		if poisonRejected.Load() {
			verdict = defense.VerdictPoisoned
		}
		return resp, verdict, nil
	case <-errgroupDone:
	case <-ctx.Done():
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

			// Cache miss: resolve A and AAAA concurrently.
			var nsAddrs []string
			var ansARecords []dns.RR
			var ansAAAARecords []dns.RR
			var addrMu sync.Mutex
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer zdnsutil.HandlePanic("Resolve NS A")
				defer wg.Done()
				ansARecords, _ = r.resolveNSAddrType(queryCtx, nsName, dns.TypeA, depth+1, forceTCP, &nsAddrs, &addrMu)
			}()

			go func() {
				defer zdnsutil.HandlePanic("Resolve NS AAAA")
				defer wg.Done()
				ansAAAARecords, _ = r.resolveNSAddrType(queryCtx, nsName, dns.TypeAAAA, depth+1, forceTCP, &nsAddrs, &addrMu)
			}()

			wg.Wait()

			if len(nsAddrs) == 0 {
				return nil
			}

			// Cache A/AAAA records so future queries hit warm cache.
			// The async latency probe below reorders them later for
			// latency-optimized cache hits.
			if r.cache != nil && len(ansARecords) > 0 {
				r.cache.Set(nsName, dns.TypeA, dns.ClassINET, nil, false, ansARecords, nil, nil, false)
			}
			if r.cache != nil && len(ansAAAARecords) > 0 {
				r.cache.Set(nsName, dns.TypeAAAA, dns.ClassINET, nil, false, ansAAAARecords, nil, nil, false)
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

	if err := g.Wait(); err != nil {
		log.Debugf("RECURSION: NS address resolution errgroup: %v", err)
	}

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
			go func() { defer zdnsutil.HandlePanic("NS addr probe"); probe.ProbeNSAddrs(r.ctx, r.cache, addrs) }()
		}
	}

	allMu.Lock()
	ShuffleSlice(allAddresses)
	allMu.Unlock()
	return allAddresses
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
// the Additional section is also collected. Returns the answer records for
// subsequent caching.
func (r *Recursive) resolveNSAddrType(ctx context.Context, nsName string, qtype uint16, depth int, forceTCP bool, nsAddrs *[]string, addrMu *sync.Mutex) (answer []dns.RR, addrs []string) {
	qr := r.resolve(ctx, Question{Name: nsName, Qtype: qtype, Qclass: dns.ClassINET}, nil, depth, forceTCP)
	if qr.Err != nil {
		return answer, addrs
	}
	addrMu.Lock()
	defer addrMu.Unlock()
	for _, rrec := range qr.Answer {
		switch a := rrec.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				*nsAddrs = append(*nsAddrs, net.JoinHostPort(a.A.String(), config.DefaultUDPPort))
				addrs = append(addrs, a.A.String())
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				*nsAddrs = append(*nsAddrs, net.JoinHostPort(a.AAAA.String(), config.DefaultUDPPort))
				addrs = append(addrs, a.AAAA.String())
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
	return qr.Answer, addrs
}
