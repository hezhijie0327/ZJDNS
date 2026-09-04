// NS-address resolution: the concurrent fan-out resolving nameserver names
// to addresses (glue, then queries), feeding the authority race.

package resolver

import (
	"context"
	"sync"
	"zjdns/config"
	"zjdns/server/resolver/probe"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/sync/errgroup"
)

func (r *Recursive) resolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS, qname string, depth int, forceTCP bool) []string {
	if len(nsRecords) == 0 {
		return nil
	}

	// Resolve NS addresses concurrently, then shuffle so the first batch is
	// not biased toward the delegation order. Latency-probed order is
	// restored on subsequent queries via the cache.  No query cap: SetLimit
	// starved the ≥2-names-done early-exit the same way it stalled
	// queryNameserversConcurrent (slow NS names held the slots while fast
	// ones queued behind the launch loop).

	resolveCtx, resolveCancel := context.WithTimeout(ctx, config.DefaultRecursiveQueryTimeout)
	defer resolveCancel()

	g, queryCtx := errgroup.WithContext(resolveCtx)

	var allMu sync.Mutex
	var allAddresses []string
	// nsNamesDone counts NS names that contributed addresses.  The fan-out
	// cancels as soon as ≥2 NS names have addresses: the walk only needs
	// reachable servers, and waiting for every NS name lets the slowest
	// resolution dictate the latency (a 9s authority timeout stalls the
	// whole walk).  Cancellation is safe — other goroutines check
	// queryCtx.Done() and exit early.
	var nsNamesDone int

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
				nsNamesDone++
				enough := nsNamesDone >= 2
				allMu.Unlock()
				if enough {
					resolveCancel()
				}
				return nil
			}

			// Cache miss: resolve A and AAAA concurrently (1 RTT — no
			// serialization).  With mqtype configured the A walk bundles
			// AAAA via RFC 10029; a supporting authority merges AAAA into
			// the A response, the warm cache (resolve()) lets the AAAA
			// walk's cache-first lookup short-circuit.
			//
			// Each family contributes AS SOON AS ITS WALK RETURNS — the
			// ≥2-names early exit and the shared address list must not wait
			// for a straggling AAAA walk whose A sibling already answered
			// (a blackholed AAAA path would otherwise pin the whole batch
			// to its 3s budget).  resolveCancel() aborts the pending sibling
			// once enough names have addresses.
			//
			// nameAddressed counts the NS name toward nsNamesDone exactly
			// once — on the first family that yields addresses (guarded by
			// allMu, shared with the cache-hit path above).
			var nameAddressed bool
			contribute := func(qtype uint16, addrs []string, records []dns.RR) {
				// Cache the family's records so future queries hit warm
				// cache; the async latency probe below reorders them later
				// for latency-optimized cache hits.
				if r.cache != nil && len(records) > 0 {
					r.cache.Set(nsName, qtype, dns.ClassINET, nil, records, nil, nil, false, 0)
					nsRecordsMu.Lock()
					if aRecordsMap == nil {
						aRecordsMap = make(map[string][]dns.RR)
						aaaaRecordsMap = make(map[string][]dns.RR)
					}
					if qtype == dns.TypeA {
						aRecordsMap[nsName] = append(aRecordsMap[nsName], records...)
					} else {
						aaaaRecordsMap[nsName] = append(aaaaRecordsMap[nsName], records...)
					}
					nsRecordsMu.Unlock()
				}
				if len(addrs) == 0 {
					return
				}
				allMu.Lock()
				allAddresses = append(allAddresses, addrs...)
				if !nameAddressed {
					nameAddressed = true
					nsNamesDone++
				}
				enough := nsNamesDone >= 2
				allMu.Unlock()
				if enough {
					resolveCancel()
				}
			}

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer zdnsutil.HandlePanic("Resolve NS A")
				defer wg.Done()
				if queryCtx.Err() != nil {
					return
				}
				var addrs []string
				var mu sync.Mutex
				records := r.resolveNSAddrType(queryCtx, nsName, dns.TypeA, depth+1, forceTCP, &addrs, &mu)
				contribute(dns.TypeA, addrs, records)
			}()

			go func() {
				defer zdnsutil.HandlePanic("Resolve NS AAAA")
				defer wg.Done()
				if queryCtx.Err() != nil {
					return
				}
				var addrs []string
				var mu sync.Mutex
				records := r.resolveNSAddrType(queryCtx, nsName, dns.TypeAAAA, depth+1, forceTCP, &addrs, &mu)
				contribute(dns.TypeAAAA, addrs, records)
			}()

			wg.Wait()
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

// resolveNSAddrType resolves a single NS address type (A or AAAA) and appends
// resolved addresses to nsAddrs under addrMu. For A queries, AAAA glue from
// the Additional section is also collected.  Concurrent walks for the same
// (name, qtype) are deduplicated by resolveNSAddrFlight — the NS-address
// cache alone cannot dedup when the addresses never resolve (unreachable
// authorities), which would amplify one lookup into ~290k queries.
func (r *Recursive) resolveNSAddrType(ctx context.Context, nsName string, qtype uint16, depth int, forceTCP bool, nsAddrs *[]string, addrMu *sync.Mutex) (answer []dns.RR) {
	res := r.resolveNSAddrFlight(ctx, nsName, qtype, depth, forceTCP)
	if len(res.addrs) > 0 {
		addrMu.Lock()
		*nsAddrs = append(*nsAddrs, res.addrs...)
		addrMu.Unlock()
	}
	return res.answer
}
