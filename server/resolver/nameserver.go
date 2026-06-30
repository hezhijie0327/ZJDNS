package resolver

import (
	"context"
	"errors"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/security"
)

func (rr *Recursive) queryNameserversConcurrent(ctx context.Context, nameservers []string, question dns.Question, ecs *edns.ECSOption, forceTCP bool, currentDomain string, detector *security.Detector) (*dns.Msg, security.Verdict, error) {
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
	normalizedQname := dnsutil.NormalizeDomain(question.Name)

	for _, ns := range nameservers {
		nsAddr := ns
		protocol := config.ProtoUDP
		if forceTCP {
			protocol = config.ProtoTCP
		}
		server := &config.UpstreamServer{Address: nsAddr, Protocol: protocol}

		g.Go(func() error {
			defer dnsutil.HandlePanic("Query nameserver")
			activeConnections.Add(1)
			defer activeConnections.Add(-1)

			select {
			case <-queryCtx.Done():
				return queryCtx.Err()
			default:
			}

			msg := rr.resolver.buildMsg(question, ecs, true, false)
			defer pool.DefaultMessagePool.Put(msg)

			subCtx, subCancel := context.WithTimeout(queryCtx, config.DefaultDNSQueryTimeout)
			defer subCancel()

			result := rr.resolver.client.ExecuteQuery(subCtx, msg, server)
			if result.Error == nil && result.Response != nil {
				rcode := result.Response.Rcode
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

					// Don't cancel other goroutines — let them
					// all complete so hijackRejected is fully
					// settled before the caller reads it.
					// This eliminates the race between first-win
					// resultChan delivery and concurrent hijack
					// detection.
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
					log.Debugf("RECURSION: ns=%s FORMERR, retrying without EDNS for %s %s", nsAddr, question.Name, dns.TypeToString[question.Qtype])

					// Build a bare query without EDNS options
					bareMsg := pool.DefaultMessagePool.Get()
					defer pool.DefaultMessagePool.Put(bareMsg)
					bareMsg.SetQuestion(dns.Fqdn(question.Name), question.Qtype)
					bareMsg.RecursionDesired = true

					retryCtx, retryCancel := context.WithTimeout(queryCtx, config.DefaultDNSQueryTimeout)
					defer retryCancel()
					retryResult := rr.resolver.client.ExecuteQuery(retryCtx, bareMsg, server)

					if retryResult.Error == nil && retryResult.Response != nil {
						retryRcode := retryResult.Response.Rcode
						if retryRcode == dns.RcodeSuccess || retryRcode == dns.RcodeNameError {
							// Reject hijacked responses in FORMERR retry path as well.
							if detector != nil && detector.IsEnabled() {
								v := detector.Validate(currentDomain, normalizedQname, retryResult.Response)
								if v == security.VerdictHijack {
									log.Debugf("RECURSION: rejecting hijacked FORMERR retry from %s", nsAddr)
									hijackRejected.Store(true)
									pool.DefaultMessagePool.Put(retryResult.Response)
									return nil
								}
							}

							select {
							case resultChan <- retryResult.Response:
								cancel()
								return nil
							case <-queryCtx.Done():
								pool.DefaultMessagePool.Put(retryResult.Response)
								return queryCtx.Err()
							}
						}
						log.Debugf("RECURSION: ns=%s FORMERR retry rcode=%s for %s %s", nsAddr, dns.RcodeToString[retryRcode], question.Name, dns.TypeToString[question.Qtype])
						pool.DefaultMessagePool.Put(retryResult.Response)
					} else if retryResult.Error != nil {
						log.Debugf("RECURSION: ns=%s FORMERR retry error=%v for %s %s", nsAddr, retryResult.Error, question.Name, dns.TypeToString[question.Qtype])
					}
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
	// cancel() already fired — queued goroutines exit via ctx.Done.
	// Running goroutines past the Done check need a brief window to
	// complete their hijack check (GFW injection arrives 1-2 ms
	// behind legitimate responses).
	<-time.After(config.DefaultHijackSettleTimeout)

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

func (rr *Recursive) resolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS, qname string, depth int, forceTCP bool) []string {
	if len(nsRecords) == 0 {
		return nil
	}

	// Process NS records in delegation order — no ShuffleSlice.
	// Latency-based ordering is applied after address resolution.

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
			defer dnsutil.HandlePanic("Resolve NS addresses")
			select {
			case <-queryCtx.Done():
				return nil
			default:
			}

			if equalFoldTrimDot(nsRecord.Ns, qname) {
				return nil
			}

			nsName := dns.Fqdn(nsRecord.Ns)

			// Try cache first — records may already be latency-probed.
			cachedAddrs := rr.lookupNSAddrsFromCache(nsName)
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
				defer dnsutil.HandlePanic("Resolve NS A")
				defer wg.Done()
				aQuestion := dns.Question{Name: nsName, Qtype: dns.TypeA, Qclass: dns.ClassINET}
				ans, _, extra, _, _, _, _, err := rr.resolve(queryCtx, aQuestion, nil, depth+1, forceTCP)
				if err != nil {
					return
				}
				addrMu.Lock()
				ansARecords = ans
				for _, rrec := range ans {
					if a, ok := rrec.(*dns.A); ok {
						nsAddrs = append(nsAddrs, config.JoinDNSPort(a.A.String()))
					}
				}
				// Also collect AAAA glue from the Additional section
				for _, rrec := range extra {
					if aaaa, ok := rrec.(*dns.AAAA); ok && strings.EqualFold(aaaa.Header().Name, nsName) {
						nsAddrs = append(nsAddrs, config.JoinDNSPort(aaaa.AAAA.String()))
					}
				}
				addrMu.Unlock()
			}()

			go func() {
				defer dnsutil.HandlePanic("Resolve NS AAAA")
				defer wg.Done()
				aaaaQuestion := dns.Question{Name: nsName, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
				ans, _, _, _, _, _, _, err := rr.resolve(queryCtx, aaaaQuestion, nil, depth+1, forceTCP)
				if err != nil {
					return
				}
				addrMu.Lock()
				ansAAAARecords = ans
				for _, rrec := range ans {
					if aaaa, ok := rrec.(*dns.AAAA); ok {
						nsAddrs = append(nsAddrs, config.JoinDNSPort(aaaa.AAAA.String()))
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
			if rr.cache != nil && len(ansARecords) > 0 {
				aCacheKey := cache.BuildCacheKey(dns.Question{Name: nsName, Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil, false)
				rr.cache.Set(aCacheKey, ansARecords, nil, nil, false, nil)
			}
			if rr.cache != nil && len(ansAAAARecords) > 0 {
				aaaaCacheKey := cache.BuildCacheKey(dns.Question{Name: nsName, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}, nil, false)
				rr.cache.Set(aaaaCacheKey, ansAAAARecords, nil, nil, false, nil)
			}

			// Accumulate records for async latency probe.
			if rr.cache != nil && (len(ansARecords) > 0 || len(ansAAAARecords) > 0) {
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

	// Merge A and AAAA records per NS name so probeAndCacheNSGlue
	// ranks all addresses together and stores them under the unified
	// latency-sorted key (nsAddrKey).
	if rr.cache != nil && (len(aRecordsMap) > 0 || len(aaaaRecordsMap) > 0) {
		combinedMap := make(map[string][]dns.RR)
		for nsName, records := range aRecordsMap {
			combinedMap[nsName] = append(combinedMap[nsName], records...)
		}
		for nsName, records := range aaaaRecordsMap {
			combinedMap[nsName] = append(combinedMap[nsName], records...)
		}
		if len(combinedMap) > 0 {
			go rr.probeAndCacheNSGlue(combinedMap)
		}
	}

	allMu.Lock()
	defer allMu.Unlock()
	return allAddresses
}

// reorderRecordsByAddrs reorders A or AAAA DNS records so that records
// matching the sorted address list come first, preserving the latency-based
// ordering. Records not in the sorted list retain their relative order at
// the end.
func reorderRecordsByAddrs(records []dns.RR, sortedAddrs []string) []dns.RR {
	if len(records) <= 1 || len(sortedAddrs) <= 1 {
		return records
	}

	// Build rank map from sorted addresses: IP → position (lower = faster).
	rank := make(map[string]int, len(sortedAddrs))
	for i, addr := range sortedAddrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip != nil {
			rank[ip.String()] = i
		}
	}

	// Default rank for IPs not in the sorted list — sorts after all known IPs.
	const unknownRank = math.MaxInt32

	sorted := make([]dns.RR, len(records))
	copy(sorted, records)
	slices.SortStableFunc(sorted, func(a, b dns.RR) int {
		ra, okA := rank[rrIP(a)]
		if !okA {
			ra = unknownRank
		}
		rb, okB := rank[rrIP(b)]
		if !okB {
			rb = unknownRank
		}
		return ra - rb
	})
	return sorted
}

// rrIP extracts the IP string from an A or AAAA record.
func rrIP(rr dns.RR) string {
	switch r := rr.(type) {
	case *dns.A:
		return r.A.String()
	case *dns.AAAA:
		return r.AAAA.String()
	default:
		return ""
	}
}

// equalFoldTrimDot compares two strings case-insensitively, ignoring a single
// trailing dot on either string. Uses sub-slicing (no allocation) instead of
// strings.TrimSuffix (which allocates when the suffix is present).
func equalFoldTrimDot(a, b string) bool {
	if len(a) > 0 && a[len(a)-1] == '.' {
		a = a[:len(a)-1]
	}
	if len(b) > 0 && b[len(b)-1] == '.' {
		b = b[:len(b)-1]
	}
	return strings.EqualFold(a, b)
}
