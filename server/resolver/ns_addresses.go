package resolver

import (
	"net"
	"net/netip"
	"slices"
	"strings"
	"zjdns/cache"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/server/resolver/probe"

	"codeberg.org/miekg/dns"
)

// ── Latency-sorted NS address cache ──────────────────────────────────────────
//
// Root servers and per-nameserver addresses are stored as regular TypeA/TypeAAAA
// cache entries by the resolution flow (or cacheRootHint for root servers).
// probe.ProbeNSAddrs runs background latency probes and stores results in
// ip_latency; sortAnswerByLatency in cache.Get() reorders records at read time.
// The pattern mirrors regular A/AAAA queries: write entry → probe → sort.

// addrsFromRRs extracts "ip:port" strings from A/AAAA records.
func addrsFromRRs(records []dns.RR) []string {
	addrs := make([]string, 0, len(records))
	for _, r := range records {
		if addr := rrToAddr(r); addr != "" {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

// rrToAddr extracts the "ip:port" string from an A or AAAA record.
func rrToAddr(r dns.RR) string {
	switch r := r.(type) {
	case *dns.A:
		return net.JoinHostPort(r.A.String(), config.DefaultUDPPort)
	case *dns.AAAA:
		return net.JoinHostPort(r.AAAA.String(), config.DefaultUDPPort)
	}
	return ""
}

// cacheRootHint writes one root server's addresses as TypeA/TypeAAAA entries.
func cacheRootHint(s cache.Store, name string, addrs []string) {
	typeGroups := make(map[uint16][]dns.RR)
	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			rr := new(dns.A)
			rr.Hdr = dns.Header{Name: name, Class: dns.ClassINET, TTL: uint32(config.DefaultRootCacheTTL)}
			rr.Addr = netip.AddrFrom4([4]byte(ip4))
			typeGroups[dns.TypeA] = append(typeGroups[dns.TypeA], rr)
		} else {
			addrObj, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			rr := new(dns.AAAA)
			rr.Hdr = dns.Header{Name: name, Class: dns.ClassINET, TTL: uint32(config.DefaultRootCacheTTL)}
			rr.Addr = addrObj
			typeGroups[dns.TypeAAAA] = append(typeGroups[dns.TypeAAAA], rr)
		}
	}
	for qtype, records := range typeGroups {
		s.Set(name, qtype, dns.ClassINET, nil, false, records, nil, nil, false)
	}
}

// getRootServers returns root server addresses ordered by probe latency.
// Each root name is looked up via the normal NS cache path; on cold start
// the name is bootstrapped from rootHints inline. Once cached, root servers
// behave identically to any other NS.
func (r *Recursive) getRootServers() []string {
	if r == nil || r.cache == nil {
		return allRootAddrs()
	}

	// Root addresses change at most monthly, but the uncached path runs 26
	// SQLite lookups (13 names × A/AAAA). Serve the memoized set within the
	// root cache TTL; the refresh path below re-probes on expiry.
	now := log.NowUnix()
	r.rootCacheMu.Lock()
	if r.rootCache != nil && now-r.rootCacheTime < int64(config.DefaultRootCacheTTL) {
		cached := r.rootCache
		r.rootCacheMu.Unlock()
		return cached
	}
	r.rootCacheMu.Unlock()

	hints := loadHints()
	all := make([]string, 0, len(hints)*2) // ~2 addrs per root server
	for name, addrs := range hints {
		cached := r.lookupNSAddrsFromCache(name, func() { cacheRootHint(r.cache, name, addrs) })
		if len(cached) == 0 {
			// Cold start for this name: write + probe + read back.
			cacheRootHint(r.cache, name, addrs)
			go func() { defer zdnsutil.HandlePanic("NS addr probe"); probe.ProbeNSAddrs(r.ctx, r.cache, addrs) }()
			cached = r.lookupNSAddrsFromCache(name, nil)
		}
		all = append(all, cached...)
	}
	if len(all) == 0 {
		return allRootAddrs()
	}
	// A transient failure of one root name (unparseable hint or a failed
	// cache read) must not permanently shrink the root set: merge the
	// remaining hints.
	if len(all) < len(hints) {
		seen := make(map[string]bool, len(all))
		for _, a := range all {
			seen[a] = true
		}
		for _, addrs := range hints {
			for _, a := range addrs {
				if !seen[a] {
					all = append(all, a)
					seen[a] = true
				}
			}
		}
	}
	// Global latency sort across families and names: per-entry sorting put
	// every IPv6 record after every IPv4 record regardless of measured
	// latency, so the fastest servers were never actually queried first.
	sorted := r.sortAddrsByLatency(all)

	// Memoize for DefaultRootCacheTTL (M6): concurrent queries race to fill
	// the cache; the loser's work is discarded, both serve the winner's set.
	r.rootCacheMu.Lock()
	r.rootCache = sorted
	r.rootCacheTime = now
	r.rootCacheMu.Unlock()
	return sorted
}

// sortAddrsByLatency orders addresses by their cached probe latency (fastest
// first), with unprobed addresses last. Latency is best-effort: any lookup
// failure leaves the order unchanged.
func (r *Recursive) sortAddrsByLatency(addrs []string) []string {
	if len(addrs) <= 1 || r.cache == nil {
		return addrs
	}
	// Pre-resolve hosts once — SplitHostPort inside the comparator would run
	// O(n log n) times. Sort an index slice so the pre-resolved hosts stay
	// positionally aligned with addrs.
	hosts := make([]string, len(addrs))
	lat := make(map[string]int64, len(addrs))
	probed := make(map[string]bool, len(addrs))
	for i, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			host = a
		}
		hosts[i] = host
		if ms, ok := r.cache.LatencyLastProbe(host); ok {
			lat[host] = ms
			probed[host] = true
		}
	}
	idx := make([]int, len(addrs))
	for i := range idx {
		idx[i] = i
	}
	slices.SortStableFunc(idx, func(i, j int) int {
		la, aOK := lat[hosts[i]]
		lb, bOK := lat[hosts[j]]
		switch {
		case aOK != bOK:
			if aOK {
				return -1 // probed first
			}
			return 1
		case aOK && la != lb:
			if la < lb {
				return -1
			}
			return 1
		}
		return 0
	})
	sorted := make([]string, len(addrs))
	for i, j := range idx {
		sorted[i] = addrs[j]
	}
	return sorted
}

// allRootAddrs returns every address from rootHints as a flat slice.
func allRootAddrs() []string {
	var all []string
	for _, addrs := range loadHints() {
		all = append(all, addrs...)
	}
	return all
}

// lookupNSAddrsFromCache looks up latency-sorted NS addresses via per-type
// TypeA/TypeAAAA entries. Triggers background refresh when the cached entry
// is expired or within the prefetch window (matching regular A/AAAA).
//
// If refreshEntry is non-nil, it is called before the latency probe to
// refresh the cache entries themselves (e.g. root hints re-write).
func (r *Recursive) lookupNSAddrsFromCache(nsName string, refreshEntry func()) []string {
	if r == nil || r.cache == nil {
		return nil
	}

	aAddrs, aRefresh := lookupCachedRRs(r.cache, nsName, dns.TypeA)
	aaaaAddrs, aaaaRefresh := lookupCachedRRs(r.cache, nsName, dns.TypeAAAA)
	addrs := make([]string, 0, len(aAddrs)+len(aaaaAddrs))
	addrs = append(addrs, aAddrs...)
	addrs = append(addrs, aaaaAddrs...)

	if (aRefresh || aaaaRefresh) && len(addrs) > 0 {
		if refreshEntry != nil {
			refreshEntry()
		}
		go func() { defer zdnsutil.HandlePanic("NS addr probe"); probe.ProbeNSAddrs(r.ctx, r.cache, addrs) }()
	}

	return addrs
}

// lookupCachedRRs fetches cached A or AAAA records for a name and converts
// them to "ip:port" strings. The needsRefresh return value is true when the
// entry is expired or within the prefetch window.
func lookupCachedRRs(store cache.Store, name string, qtype uint16) (addrs []string, needsRefresh bool) {
	entry, found, expired := store.Get(name, qtype, dns.ClassINET, nil, false)
	if !found || entry == nil || len(entry.Answer) == 0 {
		return nil, false
	}
	if expired && !entry.CanServeExpired(config.DefaultStaleMaxAge) {
		return nil, false
	}

	addrs = make([]string, 0, len(entry.Answer))
	for _, r := range entry.Answer {
		if addr := rrToAddr(r); addr != "" {
			addrs = append(addrs, addr)
		}
	}
	needsRefresh = expired || entry.ShouldPrefetch(config.DefaultPrefetchThresholdPercent)
	return addrs, needsRefresh
}
