package resolver

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/probe"
	"zjdns/server/security"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/sync/errgroup"
)

func (r *Recursive) queryNameserversConcurrent(ctx context.Context, nameservers []string, question Question, ecs *edns.ECSOption, forceTCP bool, currentDomain string, detector *security.Detector) (*dns.Msg, security.Verdict, error) {
	if len(nameservers) == 0 {
		return nil, security.VerdictClean, errors.New("no nameservers")
	}

	// Create a child context with a deadline to bound per-batch query time.
	// This prevents goroutines from lingering for the full recursive resolve
	// timeout (30s) when upstream servers are slow or unresponsive.
	deadlineCtx, deadlineCancel := context.WithTimeout(ctx, config.DefaultDNSQueryTimeout)
	defer deadlineCancel()
	queryCtx, cancel := context.WithCancel(deadlineCtx)
	defer cancel()

	resultChan := make(chan *dns.Msg, 1)
	g, queryCtx := errgroup.WithContext(queryCtx)
	limit := len(nameservers)
	if limit > config.DefaultMaxConcurrentNS {
		limit = config.DefaultMaxConcurrentNS
	}
	g.SetLimit(limit)

	var activeConnections atomic.Int32
	var hijackRejected atomic.Bool
	normalizedQname := zdnsutil.NormalizeDomain(question.Name)

	for _, ns := range nameservers {
		nsAddr := ns
		protocol := config.ProtoUDP
		if forceTCP {
			protocol = config.ProtoTCP
		}
		server := &config.UpstreamServer{Address: nsAddr, Protocol: protocol, Proxy: r.resolver.recursiveProxyURL}

		g.Go(func() error {
			defer zdnsutil.HandlePanic("Query nameserver")
			activeConnections.Add(1)
			defer activeConnections.Add(-1)

			select {
			case <-queryCtx.Done():
				return queryCtx.Err()
			default:
			}

			msg := r.resolver.buildMsg(question, ecs, true, false)
			msg.UDPSize = pool.RecursiveUDPBufferSize // larger buffer for DNSSEC-signed referrals
			defer pool.DefaultMessagePool.Put(msg)

			subCtx, subCancel := context.WithTimeout(queryCtx, config.DefaultDNSQueryTimeout)
			defer subCancel()

			result := r.resolver.client.ExecuteQuery(subCtx, msg, server)
			if result.Error == nil && result.Response != nil {
				rcode := result.Response.Rcode

				// NXDOMAIN with answer records is a malformed response —
				// the GFW injects fake A records (e.g. 1.1.1.1) into
				// negative responses. Treat as hijack.
				if rcode == dns.RcodeNameError && len(result.Response.Answer) > 0 {
					log.Debugf("RECURSION: rejecting malformed NXDOMAIN+answer from %s (hijack)", nsAddr)
					hijackRejected.Store(true)
					pool.DefaultMessagePool.Put(result.Response)
					return nil
				}
				if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
					// Validate every response against its zone.
					// GFW-injected A/AAAA/NS records at root/TLD
					// level are rejected before they can win
					// the result channel.
					if detector != nil && detector.IsEnabled() {
						v := detector.Validate(currentDomain, normalizedQname, result.Response)
						if v == security.VerdictHijack {
							log.Debugf("RECURSION: rejecting hijacked response from %s", nsAddr)
							hijackRejected.Store(true)
							pool.DefaultMessagePool.Put(result.Response)
							return nil
						}
					}

					// Send to resultChan and cancel the
					// parent context so queued goroutines
					// exit before starting work.  Running
					// goroutines past their initial Done
					// check continue — their hijack
					// validation is captured by the
					// settle timer below.
					select {
					case resultChan <- result.Response:
						cancel()
						return nil
					case <-queryCtx.Done():
						pool.DefaultMessagePool.Put(result.Response)
						return queryCtx.Err()
					}
				}

				// FORMERR fallback: some authoritative servers (e.g. Microsoft
				// mail.protection.outlook.com) reject all EDNS queries with FORMERR.
				// Retry once without EDNS to recover (RFC 6891 §6.2.2).
				if rcode == dns.RcodeFormatError {
					pool.DefaultMessagePool.Put(result.Response)
					r.retryWithoutEDNS(queryCtx, resultChan, cancel, server, question, nsAddr, detector, currentDomain, normalizedQname, &hijackRejected)
					return nil
				}

				log.Debugf("RECURSION: ns=%s rcode=%s for %s %s", nsAddr, dns.RcodeToString[rcode], question.Name, dns.TypeToString[question.Qtype])
				pool.DefaultMessagePool.Put(result.Response)
			} else if result.Error != nil {
				log.Debugf("RECURSION: ns=%s error=%v for %s %s", nsAddr, result.Error, question.Name, dns.TypeToString[question.Qtype])
			}
			return nil
		})
	}

	// Let in-flight goroutines settle before reading hijackRejected.
	// cancel() may have fired via the resultChan path, stopping queued
	// goroutines from starting.  Running goroutines past their initial
	// Done check continue to completion — the hijack check needs a
	// brief window to catch GFW-injected responses that arrive 1-2 ms
	// behind legitimate ones.
	//
	// Use ctx (parent) instead of queryCtx so the settle window is
	// always honoured — queryCtx is cancelled by the first clean
	// response and would short-circuit the hijack detection window.
	hijackTimer := time.NewTimer(config.DefaultHijackSettleTimeout)
	defer hijackTimer.Stop()
	select {
	case <-hijackTimer.C:
	case <-ctx.Done():
	}

	verdict := security.VerdictClean
	if hijackRejected.Load() {
		verdict = security.VerdictHijack
	}

	// Try a non-blocking read first.  After cancel(), a result was
	// written to resultChan — it should be available immediately.
	// Avoid racing with queryCtx.Done() in the select (when both are
	// ready, Go's select picks randomly, potentially discarding the
	// result in favour of a cancelled-context error).
	select {
	case result := <-resultChan:
		if result != nil {
			return result, verdict, nil
		}
		log.Debugf("RECURSION: all %d nameservers failed for %s (zone=%s)", len(nameservers), question.Name, currentDomain)
		return nil, verdict, errors.New("no successful response")
	default:
	}

	// No result yet — wait with the context deadline.
	select {
	case result := <-resultChan:
		if result != nil {
			return result, verdict, nil
		}
		log.Debugf("RECURSION: all %d nameservers failed for %s (zone=%s, deadline exceeded)", len(nameservers), question.Name, currentDomain)
		return nil, verdict, errors.New("no successful response")
	case <-queryCtx.Done():
		log.Debugf("RECURSION: context cancelled while waiting for %s (zone=%s)", question.Name, currentDomain)
		return nil, verdict, queryCtx.Err()
	}
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

			if isEqualFoldTrimDot(nsRecord.Ns, qname) {
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
				aQuestion := Question{Name: nsName, Qtype: dns.TypeA, Qclass: dns.ClassINET}
				qr := r.resolve(queryCtx, aQuestion, nil, depth+1, forceTCP)
				if qr.Err != nil {
					return
				}
				addrMu.Lock()
				ansARecords = qr.Answer
				for _, rrec := range qr.Answer {
					if a, ok := rrec.(*dns.A); ok {
						nsAddrs = append(nsAddrs, zdnsutil.JoinDNSPort(a.A.String()))
					}
				}
				// Also collect AAAA glue from the Additional section
				for _, rrec := range qr.Additional {
					if aaaa, ok := rrec.(*dns.AAAA); ok && strings.EqualFold(aaaa.Header().Name, nsName) {
						nsAddrs = append(nsAddrs, zdnsutil.JoinDNSPort(aaaa.AAAA.String()))
					}
				}
				addrMu.Unlock()
			}()

			go func() {
				defer zdnsutil.HandlePanic("Resolve NS AAAA")
				defer wg.Done()
				aaaaQuestion := Question{Name: nsName, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
				qr := r.resolve(queryCtx, aaaaQuestion, nil, depth+1, forceTCP)
				if qr.Err != nil {
					return
				}
				addrMu.Lock()
				ansAAAARecords = qr.Answer
				for _, rrec := range qr.Answer {
					if aaaa, ok := rrec.(*dns.AAAA); ok {
						nsAddrs = append(nsAddrs, zdnsutil.JoinDNSPort(aaaa.AAAA.String()))
					}
				}
				addrMu.Unlock()
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

	_ = g.Wait()

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
			go probe.ProbeNSAddrs(r.cache, addrs)
		}
	}

	allMu.Lock()
	addresses := ShuffleSlice(allAddresses)
	allMu.Unlock()
	return addresses
}

// reorderRecordsByAddrs reorders A or AAAA DNS records so that records
// matching the sorted address list come first, preserving the latency-based
// ordering. Records not in the sorted list retain their relative order at
// the end.

// rrIP extracts the IP string from an A or AAAA record.

// isEqualFoldTrimDot compares two strings case-insensitively, ignoring a single
// trailing dot on either string. Uses sub-slicing (no allocation) instead of
// strings.TrimSuffix (which allocates when the suffix is present).
func isEqualFoldTrimDot(a, b string) bool {
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
func (r *Recursive) retryWithoutEDNS(ctx context.Context, resultChan chan<- *dns.Msg, cancel context.CancelFunc, server *config.UpstreamServer, question Question, nsAddr string, detector *security.Detector, currentDomain, normalizedQname string, hijackRejected *atomic.Bool) {
	log.Debugf("RECURSION: ns=%s FORMERR, retrying without EDNS for %s %s", nsAddr, question.Name, dns.TypeToString[question.Qtype])

	bareMsg := pool.DefaultMessagePool.Get()
	defer pool.DefaultMessagePool.Put(bareMsg)
	dnsutil.SetQuestion(bareMsg, dnsutil.Fqdn(question.Name), question.Qtype)
	bareMsg.RecursionDesired = true

	retryCtx, retryCancel := context.WithTimeout(ctx, config.DefaultDNSQueryTimeout)
	defer retryCancel()
	retryResult := r.resolver.client.ExecuteQuery(retryCtx, bareMsg, server)

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
		pool.DefaultMessagePool.Put(retryResult.Response)
		return
	}

	// Reject hijacked responses in FORMERR retry path as well.
	if detector != nil && detector.IsEnabled() {
		v := detector.Validate(currentDomain, normalizedQname, retryResult.Response)
		if v == security.VerdictHijack {
			log.Debugf("RECURSION: rejecting hijacked FORMERR retry from %s", nsAddr)
			hijackRejected.Store(true)
			pool.DefaultMessagePool.Put(retryResult.Response)
			return
		}
	}

	select {
	case resultChan <- retryResult.Response:
		cancel()
	case <-ctx.Done():
		pool.DefaultMessagePool.Put(retryResult.Response)
	}
}
