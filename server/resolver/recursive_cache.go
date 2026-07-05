package resolver

import (
	"net"
	"net/netip"
	"strings"

	"codeberg.org/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/server/probe"
)

// ── Latency-sorted NS address cache ──────────────────────────────────────────
//
// Root servers and per-nameserver addresses are stored as regular TypeA/TypeAAAA
// cache entries by the resolution flow (or cacheRootServers for root servers).
// probe.ProbeNSAddrs runs background latency probes and stores results in
// ip_latency; sortAnswerByLatency in cache.Get() reorders records at read time.
// The pattern mirrors regular A/AAAA queries: write entry → probe → sort.

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
	// Check IPv4 first with To4() because net.ParseIP returns a 16-byte
	// representation for all addresses; netip.AddrFromSlice would see an
	// IPv4-mapped-IPv6 and treat it as IPv6, making all A records AAAA.
	if ip4 := ip.To4(); ip4 != nil {
		rr := new(dns.A)
		rr.Hdr = dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl}
		rr.Addr = netip.AddrFrom4([4]byte(ip4))
		return rr
	}
	addrObj, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil
	}
	rr := new(dns.AAAA)
	rr.Hdr = dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl}
	rr.Addr = addrObj
	return rr
}

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

// cacheRootServers writes the static root server list as TypeA/TypeAAAA
// entries so getRootServers() can use the normal cache.Get() path.
func (r *Recursive) cacheRootServers() {
	typeGroups := make(map[uint16][]dns.RR)
	for _, addr := range DefaultRootServers {
		if rr := addrToRR(".", addr, uint32(config.DefaultRootCacheTTL)); rr != nil {
			qtype := dns.RRToType(rr)
			typeGroups[qtype] = append(typeGroups[qtype], rr)
		}
	}
	for qtype, records := range typeGroups {
		r.cache.Set(".", qtype, dns.ClassINET, nil, false, records, nil, nil, false, cache.SetOptions{})
	}
	log.Debugf("RECURSION: cached %d root servers (%d A + %d AAAA)",
		len(DefaultRootServers), len(typeGroups[dns.TypeA]), len(typeGroups[dns.TypeAAAA]))
}

// getRootServers returns root servers ordered by probe latency.
func (r *Recursive) getRootServers() []string {
	if r == nil {
		return DefaultRootServers
	}

	aAddrs, aRefresh := lookupCachedRRs(r.cache, ".", dns.TypeA)
	aaaaAddrs, aaaaRefresh := lookupCachedRRs(r.cache, ".", dns.TypeAAAA)
	addrs := append(aAddrs, aaaaAddrs...)

	if len(addrs) == 0 {
		// Cold start: write entries, probe latency, read back.
		log.Debugf("RECURSION: root cache cold start, writing static root list")
		r.cacheRootServers()
		go probe.ProbeNSAddrs(r.cache, ".", DefaultRootServers)
		aAddrs, _ = lookupCachedRRs(r.cache, ".", dns.TypeA)
		aaaaAddrs, _ = lookupCachedRRs(r.cache, ".", dns.TypeAAAA)
		addrs = append(aAddrs, aaaaAddrs...)
	} else if aRefresh || aaaaRefresh {
		go probe.ProbeNSAddrs(r.cache, ".", append(aAddrs, aaaaAddrs...))
	}

	if len(addrs) == 0 {
		return DefaultRootServers
	}
	return addrs
}

// lookupNSAddrsFromCache looks up latency-sorted NS addresses via per-type
// TypeA/TypeAAAA entries. Triggers a background latency re-probe when the
// cached entry is expired or within the prefetch window (matching the
// regular A/AAAA prefetch behaviour).
func (r *Recursive) lookupNSAddrsFromCache(nsName string) []string {
	if r == nil || r.cache == nil {
		return nil
	}

	aAddrs, aRefresh := lookupCachedRRs(r.cache, nsName, dns.TypeA)
	aaaaAddrs, aaaaRefresh := lookupCachedRRs(r.cache, nsName, dns.TypeAAAA)
	addrs := make([]string, 0, len(aAddrs)+len(aaaaAddrs))
	addrs = append(addrs, aAddrs...)
	addrs = append(addrs, aaaaAddrs...)

	if (aRefresh || aaaaRefresh) && len(addrs) > 0 {
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
