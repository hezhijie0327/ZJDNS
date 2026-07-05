package resolver

import (
	"net"
	"net/netip"
	"strings"

	"codeberg.org/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/server/probe"
)

// ── Latency-sorted NS address cache ──────────────────────────────────────────
//
// Root servers and per-nameserver addresses are stored as regular TypeA/TypeAAAA
// cache entries by the resolution flow (or cacheRootServers for root servers).
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
		return net.JoinHostPort(r.A.String(), config.DefaultDNSPort)
	case *dns.AAAA:
		return net.JoinHostPort(r.AAAA.String(), config.DefaultDNSPort)
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
		s.Set(name, qtype, dns.ClassINET, nil, false, records, nil, nil, false, cache.SetOptions{})
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

	var all []string
	for name, addrs := range rootHints {
		cached := r.lookupNSAddrsFromCache(name, func() { cacheRootHint(r.cache, name, addrs) })
		if len(cached) == 0 {
			// Cold start for this name: write + probe + read back.
			cacheRootHint(r.cache, name, addrs)
			go probe.ProbeNSAddrs(r.cache, name, addrs)
			cached = r.lookupNSAddrsFromCache(name, nil)
		}
		all = append(all, cached...)
	}
	if len(all) == 0 {
		return allRootAddrs()
	}
	return all
}

// allRootAddrs returns every address from rootHints as a flat slice.
func allRootAddrs() []string {
	var all []string
	for _, addrs := range rootHints {
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
		go probe.ProbeNSAddrs(r.cache, nsName, addrs)
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
