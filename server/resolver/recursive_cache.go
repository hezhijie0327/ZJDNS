package resolver

import (
	"context"
	"net"
	"net/netip"

	"strings"

	"codeberg.org/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/server/probe"
)

// ── Latency-sorted NS address cache ──────────────────────────────────────────
//
// Root servers and per-nameserver addresses are stored as normal cache entries
// (qname + TypeNone sentinel). Records are stored in probe-sorted order at
// Set() time so wire format preserves the latency ordering. Latency values
// are also stored in the record_latency table for analytics.

// addrToRR converts an "ip:port" string to an A or AAAA DNS record.
func addrToRR(name, addr string, ttl uint32) dns.RR {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return nil
	}
	addrObj, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil
	}
	if addrObj.Is4() {
		rr := new(dns.A)
		rr.Hdr = dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl}
		rr.Addr = addrObj
		return rr
	}
	rr := new(dns.AAAA)
	rr.Hdr = dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl}
	rr.Addr = addrObj
	return rr
}

// addrsToRRs converts "ip:port" strings to A/AAAA DNS records.
func addrsToRRs(name string, addrs []string, ttl uint32) []dns.RR {
	records := make([]dns.RR, 0, len(addrs))
	for _, addr := range addrs {
		if rr := addrToRR(name, addr, ttl); rr != nil {
			records = append(records, rr)
		}
	}
	return records
}

// readAddrsFromEntry extracts "ip:port" strings from the Answer records
// of a cache entry. Records are already sorted by latency at Set() time
// and the ordering is preserved in wire format; sortAnswerByLatency in
// Get() handles the normal DNS query path.
func readAddrsFromEntry(entry *cache.Entry) []string {
	if entry == nil || len(entry.Answer) == 0 {
		return nil
	}
	addrs := make([]string, 0, len(entry.Answer))
	for _, r := range entry.Answer {
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
		return net.JoinHostPort(r.A.String(), config.DefaultDNSPort)
	case *dns.AAAA:
		return net.JoinHostPort(r.AAAA.String(), config.DefaultDNSPort)
	}
	return ""
}

// ipFromAddr extracts the net.IP from an "ip:port" string.
func ipFromAddr(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

// probeAndCacheAddrs probes the given addresses, stores latency-sorted A/AAAA
// records under the zone name with TypeNone sentinel, and persists latency
// values to record_latency for analytics.
func (r *Recursive) probeAndCacheAddrs(zone string, addrs []string) {
	defer dnsutil.HandlePanic("probeAndCacheAddrs")
	if len(addrs) <= 1 || r.cache == nil {
		return
	}
	ctx := r.bgCtx
	if ctx == nil {
		ctx = context.Background()
	}

	// Probe and get latency values.
	ips := make([]net.IP, 0, len(addrs))
	ipToAddr := make(map[string]string, len(addrs))
	for _, addr := range addrs {
		if ip := ipFromAddr(addr); ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
			ips = append(ips, ip)
			ipToAddr[ip.String()] = addr
		}
	}
	if len(ips) <= 1 {
		return
	}

	probeCtx, cancel := context.WithTimeout(ctx, config.DefaultInfraProbeTimeout)
	defer cancel()
	sortedIPs, latencies := probe.SortIPsByLatencyMap(probeCtx, ips)
	if len(sortedIPs) == 0 {
		return
	}

	// Build sorted address list for latency ranking.
	sortedAddrs := make([]string, 0, len(sortedIPs))
	seen := make(map[string]bool, len(sortedIPs))
	for _, ip := range sortedIPs {
		if addr, ok := ipToAddr[ip.String()]; ok && !seen[addr] {
			sortedAddrs = append(sortedAddrs, addr)
			seen[addr] = true
		}
	}
	// Append unprobed entries at the end.
	for _, addr := range addrs {
		if !seen[addr] {
			sortedAddrs = append(sortedAddrs, addr)
			seen[addr] = true
		}
	}

	// Store as normal A/AAAA records under TypeNone sentinel.
	rrRecords := addrsToRRs(zone, sortedAddrs, uint32(config.DefaultNSLatencyTTL))
	r.cache.Set(zone, dns.TypeNone, dns.ClassINET, nil, false, rrRecords, nil, nil, false, cache.SetOptions{})

	// Update latency_ms for probed IPs.
	for ipStr, lat := range latencies {
		if addr, ok := ipToAddr[ipStr]; ok {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				continue
			}
			cleanIP := net.ParseIP(strings.Trim(host, "[]"))
			if cleanIP != nil {
				r.cache.UpdateLatency(zone, dns.TypeNone, dns.ClassINET, nil, false, cleanIP.String(), lat)
			}
		}
	}
}

// getRootServers returns root servers ordered by probe latency.
func (r *Recursive) getRootServers() []string {
	if r == nil {
		return DefaultRootServers
	}

	if r.cache != nil {
		if entry, found, expired := r.cache.Get(".", dns.TypeNone, dns.ClassINET, nil, false); found && entry != nil {
			if addrs := readAddrsFromEntry(entry); len(addrs) > 0 {
				if expired {
					r.bgGroup.Go(func() error { r.probeRootAddrs(); return nil })
				}
				return addrs
			}
		}
	}

	r.bgGroup.Go(func() error { r.probeRootAddrs(); return nil })
	return ShuffleSlice(DefaultRootServers)
}

func (r *Recursive) probeRootAddrs() {
	log.Debugf("RECURSION: probing root server latency (%d addresses)", len(DefaultRootServers))
	r.probeAndCacheAddrs(".", DefaultRootServers)
}

func (r *Recursive) refreshNSAddrOrder(nsName string, addrs []string) {
	log.Debugf("RECURSION: refreshing latency order for NS %s (%d addresses)", nsName, len(addrs))
	r.probeAndCacheAddrs(nsName, addrs)
}

// probeAndCacheNSGlue runs latency probes against all IPs in the nsGlue map
// and caches latency-sorted A/AAAA records, with latency values stored in
// record_latency for analytics.
func (r *Recursive) probeAndCacheNSGlue(nsGlue map[string][]dns.RR) {
	defer dnsutil.HandlePanic("probeAndCacheNSGlue")
	if r.cache == nil || len(nsGlue) == 0 {
		return
	}

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

	probeCtx, cancel := context.WithTimeout(ctx, config.DefaultInfraProbeTimeout)
	defer cancel()

	// Probe all IPs to get latency ranking.
	ips := make([]net.IP, 0, len(allAddrs))
	ipToAddr := make(map[string]string, len(allAddrs))
	for _, addr := range allAddrs {
		if ip := ipFromAddr(addr); ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
			ips = append(ips, ip)
			ipToAddr[ip.String()] = addr
		}
	}

	sortedIPs, latencies := probe.SortIPsByLatencyMap(probeCtx, ips)
	if len(sortedIPs) == 0 {
		return
	}

	// Build global ranking.
	addrRank := make(map[string]int, len(sortedIPs))
	for i, ip := range sortedIPs {
		if addr, ok := ipToAddr[ip.String()]; ok {
			addrRank[addr] = i
		}
	}

	for nsName, records := range nsGlue {
		// Reorder records by global latency ranking.
		sortedRecords := reorderRecordsByAddrRank(records, addrRank)
		if len(sortedRecords) == 0 {
			continue
		}

		// Store under TypeNone unified key.
		r.cache.Set(nsName, dns.TypeNone, dns.ClassINET, nil, false, sortedRecords, nil, nil, false, cache.SetOptions{})
		log.Debugf("RECURSION: async-cached %d latency-sorted NS addresses for %s", len(sortedRecords), nsName)

		// Update latency_ms for probed IPs.
		for _, rrec := range sortedRecords {
			if ip, ok := dnsutil.ExtractIPString(rrec); ok {
				if lat, ok := latencies[ip]; ok {
					r.cache.UpdateLatency(nsName, dns.TypeNone, dns.ClassINET, nil, false, ip, lat)
				}
			}
		}

		// Per-type cache entries with intra-type ordering.
		typeGroups := make(map[uint16][]dns.RR)
		for _, r := range sortedRecords {
			qtype := dns.RRToType(r)
			typeGroups[qtype] = append(typeGroups[qtype], r)
		}
		for qtype, typeRecords := range typeGroups {
			r.cache.Set(nsName, qtype, dns.ClassINET, nil, false, typeRecords, nil, nil, false, cache.SetOptions{})
		}
	}
}

// reorderRecordsByAddrRank reorders RRs by their address rank in the global
// latency probe results.
func reorderRecordsByAddrRank(records []dns.RR, addrRank map[string]int) []dns.RR {
	type indexed struct {
		rr   dns.RR
		addr string
		rank int
	}
	items := make([]indexed, 0, len(records))
	for _, r := range records {
		addr := rrToAddr(r)
		rank, ok := addrRank[addr]
		if !ok {
			rank = len(addrRank) // unprobed → end
		}
		items = append(items, indexed{rr: r, addr: addr, rank: rank})
	}

	// Sort by rank, preserving original order for ties.
	for i := 1; i < len(items); i++ {
		j := i
		for j > 0 && items[j-1].rank > items[j].rank {
			items[j-1], items[j] = items[j], items[j-1]
			j--
		}
	}

	result := make([]dns.RR, len(items))
	for i, item := range items {
		result[i] = item.rr
	}
	return result
}

// lookupNSAddrsFromCache looks up latency-sorted NS addresses via the TypeNone
// unified key. Falls back to per-type A/AAAA cache entries on cold start.
func (r *Recursive) lookupNSAddrsFromCache(nsName string) []string {
	if r == nil || r.cache == nil {
		return nil
	}

	// Fast path: TypeNone entry with latency-sorted records.
	if entry, found, expired := r.cache.Get(nsName, dns.TypeNone, dns.ClassINET, nil, false); found && entry != nil {
		if addrs := readAddrsFromEntry(entry); len(addrs) > 0 {
			if expired {
				r.bgGroup.Go(func() error { r.refreshNSAddrOrder(nsName, addrs); return nil })
			}
			return addrs
		}
	}

	// Fallback: per-type cache entries.
	aAddrs := lookupCachedRRs(r.cache, nsName, dns.TypeA)
	aaaaAddrs := lookupCachedRRs(r.cache, nsName, dns.TypeAAAA)
	addrs := make([]string, 0, len(aAddrs)+len(aaaaAddrs))
	addrs = append(addrs, aAddrs...)
	addrs = append(addrs, aaaaAddrs...)
	return addrs
}

// lookupCachedRRs fetches cached A or AAAA records for a name and converts
// them to "ip:port" strings.
func lookupCachedRRs(store cache.Store, name string, qtype uint16) []string {
	entry, found, expired := store.Get(name, qtype, dns.ClassINET, nil, false)
	if !found || entry == nil || len(entry.Answer) == 0 {
		return nil
	}
	if expired && !entry.CanServeExpired(config.DefaultStaleMaxAge) {
		return nil
	}

	addrs := make([]string, 0, len(entry.Answer))
	for _, r := range entry.Answer {
		if addr := rrToAddr(r); addr != "" {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}
