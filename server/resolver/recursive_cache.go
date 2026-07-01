package resolver

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/server/latency"
)

// ── Unified latency-sorted address cache ──────────────────────────────────────
//
// Both root servers (zone ".") and per-nameserver addresses share a single key
// space: dns:_addrs:<zone>:0:1.  Each entry stores TXT records whose Txt values
// are "ip:port" strings ordered by measured latency (fastest first, across both
// address families).  This is separate from per-type (A/AAAA) cache entries so
// the NS lookup path always gets the true latency ranking without heuristics.

// nsAddrKey returns the unified cache key for latency-sorted server addresses.
func nsAddrKey(zone string) string {
	return nsAddrKeyPrefix + dnsutil.NormalizeDomain(zone) + nsAddrKeySuffix
}

// addrsToTXTRecords converts "ip:port" strings to TXT DNS records with the
// given TTL (in seconds).  The TTL controls how frequently the latency order
// is refreshed: a shorter TTL means more frequent re-probes.
func addrsToTXTRecords(name string, addrs []string, ttlSeconds int) []dns.RR {
	records := make([]dns.RR, 0, len(addrs))
	for _, addr := range addrs {
		records = append(records, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(ttlSeconds)},
			Txt: []string{addr},
		})
	}
	return records
}

// readTXTAddrs extracts "ip:port" strings from a cache entry stored by
// addrsToTXTRecords (or by probeAndCacheNSGlue).
func readTXTAddrs(entry *cache.CacheEntry) []string {
	if entry == nil || len(entry.Answer) == 0 {
		return nil
	}
	records := cache.ExpandRecords(entry.Answer)
	addrs := make([]string, 0, len(records))
	for _, r := range records {
		if txt, ok := r.(*dns.TXT); ok && len(txt.Txt) > 0 {
			addrs = append(addrs, txt.Txt...)
		}
	}
	return addrs
}

// rrToAddr extracts the "ip:port" string from an A or AAAA record. Returns
// empty string for other record types.
func rrToAddr(r dns.RR) string {
	switch r := r.(type) {
	case *dns.A:
		return net.JoinHostPort(r.A.String(), config.DefaultDNSPort)
	case *dns.AAAA:
		return net.JoinHostPort(r.AAAA.String(), config.DefaultDNSPort)
	}
	return ""
}

// probeAndCacheAddrs probes the given addresses, sorts them by latency, and
// stores the result under nsAddrKey(zone). Shared by root (zone=".") and
// per-nameserver (zone=<nsName>) refresh paths.
func (r *Recursive) probeAndCacheAddrs(zone string, addrs []string) {
	defer dnsutil.HandlePanic("probeAndCacheAddrs")
	if len(addrs) <= 1 || r.cache == nil {
		return
	}
	ctx := r.bgCtx
	if ctx == nil {
		ctx = context.Background()
	}
	sorted := sortAddrsByLatency(ctx, addrs, config.DefaultInfraProbeTimeout)
	if len(sorted) > 0 {
		txtRecords := addrsToTXTRecords(zone, sorted, config.DefaultNSLatencyTTL)
		r.cache.Set(nsAddrKey(zone), txtRecords, nil, nil, false, nil)
	}
}

// getRootServers returns root servers ordered by latency. It reads from the
// unified nsAddrKey(".") — the same cache space as per-nameserver addresses.
// On cache miss (cold start) it returns DefaultRootServers and triggers an
// initial probe. On expiry it serves the stale order and triggers a background
// re-probe — matching the NS refresh pattern in lookupNSAddrsFromCache.
func (r *Recursive) getRootServers() []string {
	if r == nil {
		return DefaultRootServers
	}

	// Serve from unified cache (hit, expired, or miss).
	if r.cache != nil {
		if entry, found, expired := r.cache.Get(nsAddrKey(".")); found && entry != nil {
			if addrs := readTXTAddrs(entry); len(addrs) > 0 {
				if expired {
					go r.probeRootAddrs()
				}
				return addrs
			}
		}
	}

	// Cold start: probe in background, return IANA order.
	go r.probeRootAddrs()
	return DefaultRootServers
}

// probeRootAddrs re-probes the full IANA root server list. Delegates to
// probeAndCacheAddrs so root and per-NS refresh share the same code path.
func (r *Recursive) probeRootAddrs() {
	log.Debugf("RECURSION: probing root server latency (%d addresses)", len(DefaultRootServers))
	r.probeAndCacheAddrs(".", DefaultRootServers)
}

// refreshNSAddrOrder re-probes a single NS name's addresses. Delegates to
// probeAndCacheAddrs so root and per-NS refresh share the same code path.
func (r *Recursive) refreshNSAddrOrder(nsName string, addrs []string) {
	log.Debugf("RECURSION: refreshing latency order for NS %s (%d addresses)", nsName, len(addrs))
	r.probeAndCacheAddrs(nsName, addrs)
}

// probeAndCacheNSGlue runs latency probes against all IPs in the nsGlue map
// and caches the latency-sorted results. Each NS name gets an entry under
// nsAddrKey(nsName) — the unified key space shared with root servers.
// Per-type cache entries (A/AAAA) are also updated with intra-type ordering
// for normal DNS query responses.
func (r *Recursive) probeAndCacheNSGlue(nsGlue map[string][]dns.RR) {
	defer dnsutil.HandlePanic("probeAndCacheNSGlue")
	if r.cache == nil || len(nsGlue) == 0 {
		return
	}

	// Concurrency is bounded by the latency package's own semaphore
	// (config.DefaultMaxProbes) and dedup cache — no additional locking
	// needed at this level; the dedup cache prevents redundant probes
	// for identical IP sets.

	// Collect all addresses from all NS names so they are ranked together.
	var allAddrs []string
	for _, records := range nsGlue {
		for _, rrec := range records {
			if addr := rrToAddr(rrec); addr != "" {
				allAddrs = append(allAddrs, addr)
			}
		}
	}

	if len(allAddrs) <= 1 {
		return
	}

	ctx := r.bgCtx
	if ctx == nil {
		ctx = context.Background()
	}
	sorted := sortAddrsByLatency(ctx, allAddrs, config.DefaultInfraProbeTimeout)
	if len(sorted) == 0 {
		return
	}

	// For each NS name: reorder all records by global latency ranking,
	// cache under the unified nsAddrKey, and update per-type entries.
	for nsName, records := range nsGlue {
		sortedRecords := reorderRecordsByAddrs(records, sorted)
		if len(sortedRecords) == 0 {
			continue
		}

		// Build "ip:port" strings in latency order for the unified key.
		sortedAddrs := make([]string, 0, len(sortedRecords))
		for _, r := range sortedRecords {
			if addr := rrToAddr(r); addr != "" {
				sortedAddrs = append(sortedAddrs, addr)
			}
		}

		// Unified latency-sorted key (shared format with root servers).
		txtRecords := addrsToTXTRecords(nsName, sortedAddrs, config.DefaultNSLatencyTTL)
		r.cache.Set(nsAddrKey(nsName), txtRecords, nil, nil, false, nil)
		log.Debugf("RECURSION: async-cached %d latency-sorted NS addresses for %s", len(txtRecords), nsName)

		// Also update per-type cache entries (A/AAAA) with intra-type
		// latency ordering for normal DNS query responses.
		typeGroups := make(map[uint16][]dns.RR)
		for _, r := range sortedRecords {
			qtype := r.Header().Rrtype
			typeGroups[qtype] = append(typeGroups[qtype], r)
		}
		for qtype, typeRecords := range typeGroups {
			cacheKey := cache.BuildCacheKey(dns.Question{Name: nsName, Qtype: qtype, Qclass: dns.ClassINET}, nil, false)
			r.cache.Set(cacheKey, typeRecords, nil, nil, false, nil)
		}
	}
}

// sortAddrsByLatency extracts IPs from addr:port strings, probes them
// concurrently, and returns the addresses sorted fastest-first. Addresses
// without valid public IPs are placed at the end in original order.
func sortAddrsByLatency(parentCtx context.Context, addresses []string, timeout time.Duration) []string {
	if len(addresses) <= 1 {
		return addresses
	}

	// Extract valid, public IPs alongside their original addresses.
	type entry struct {
		addr string
		ip   net.IP
	}
	entries := make([]entry, 0, len(addresses))
	probeIPs := make([]net.IP, 0, len(addresses))

	for _, addr := range addresses {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
			entries = append(entries, entry{addr: addr, ip: ip})
			probeIPs = append(probeIPs, ip)
		}
	}

	if len(probeIPs) <= 1 {
		return addresses
	}

	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	sortedIPs := latency.SortIPsByLatency(ctx, probeIPs)

	// Map IPs back to original addresses preserving probe order.
	ipToAddr := make(map[string]string, len(entries))
	for _, e := range entries {
		ipToAddr[e.ip.String()] = e.addr
	}

	result := make([]string, 0, len(addresses))
	seen := make(map[string]bool, len(addresses))
	for _, ip := range sortedIPs {
		if addr, ok := ipToAddr[ip.String()]; ok && !seen[addr] {
			result = append(result, addr)
			seen[addr] = true
		}
	}
	// Append unprobed entries at the end.
	for _, addr := range addresses {
		if !seen[addr] {
			result = append(result, addr)
			seen[addr] = true
		}
	}

	return result
}

// lookupNSAddrsFromCache looks up latency-sorted NS addresses via the unified
// nsAddrKey. When the entry is expired, it serves the stale order and
// triggers a background re-probe — matching the root server refresh pattern.
// Falls back to per-type (A/AAAA) cache entries when the probe hasn't
// populated the unified key yet (cold start).
func (r *Recursive) lookupNSAddrsFromCache(nsName string) []string {
	if r == nil || r.cache == nil {
		return nil
	}

	// Fast path: unified latency-sorted key (TXT records in probe order).
	if entry, found, expired := r.cache.Get(nsAddrKey(nsName)); found && entry != nil {
		if addrs := readTXTAddrs(entry); len(addrs) > 0 {
			if expired {
				go r.refreshNSAddrOrder(nsName, addrs)
			}
			return addrs
		}
	}

	// Fallback: per-type cache entries (unsorted or intra-type sorted only).
	aAddrs := lookupCachedRRs(r.cache, nsName, dns.TypeA)
	aaaaAddrs := lookupCachedRRs(r.cache, nsName, dns.TypeAAAA)
	if len(aAddrs) == 0 && len(aaaaAddrs) == 0 {
		return nil
	}
	addrs := make([]string, 0, len(aAddrs)+len(aaaaAddrs))
	addrs = append(addrs, aAddrs...)
	addrs = append(addrs, aaaaAddrs...)
	return addrs
}

// lookupCachedRRs fetches cached A or AAAA records for a name and converts
// them to "ip:port" strings, preserving the cache entry's record order.
// Expired entries within the serve-stale window (config.DefaultStaleMaxAge)
// are still returned to avoid triggering expensive re-resolution for NS
// addresses whose TTL just expired — NS IPs change very rarely.
func lookupCachedRRs(store cache.Store, name string, qtype uint16) []string {
	q := dns.Question{Name: name, Qtype: qtype, Qclass: dns.ClassINET}
	key := cache.BuildCacheKey(q, nil, false)
	entry, found, expired := store.Get(key)
	if !found || entry == nil || len(entry.Answer) == 0 {
		return nil
	}
	if expired && !entry.CanServeExpired(config.DefaultStaleMaxAge) {
		return nil
	}

	records := cache.ExpandRecords(entry.Answer)
	addrs := make([]string, 0, len(records))
	for _, r := range records {
		if addr := rrToAddr(r); addr != "" {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}
