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
// Root servers and per-nameserver addresses are stored as regular TypeA/TypeAAAA
// cache entries. Latency values are stored in the ECS-agnostic ip_latency table;
// sortAnswerByLatency in cache.Get() reorders records by latency at read time.
// Probing is triggered on every discovery of new NS addresses during recursive
// resolution — no separate TTL-based refresh mechanism is needed.

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

// probeAndCacheAddrs probes the given addresses, stores them as per-type
// TypeA/TypeAAAA entries, and persists latency values to ip_latency with
// the actual qtype. Used for root servers (cold start) — NS addresses are
// handled by the resolution flow + probeAndCacheNSGlue.
//
// No pre-sorting is needed: sortAnswerByLatency reorders records via
// ip_latency at Get() time.
func (r *Recursive) probeAndCacheAddrs(zone string, addrs []string) {
	defer dnsutil.HandlePanic("probeAndCacheAddrs")
	if len(addrs) <= 1 || r.cache == nil {
		return
	}
	ctx := r.bgCtx
	if ctx == nil {
		ctx = context.Background()
	}

	// Probe public IPs for latency.
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
	_, latencies := probe.SortIPsByLatencyMap(probeCtx, ips)

	// Write per-type entries for all addresses (probed + unprobed).
	typeGroups := make(map[uint16][]dns.RR)
	for _, addr := range addrs {
		if rr := addrToRR(zone, addr, 3600); rr != nil {
			qtype := dns.RRToType(rr)
			typeGroups[qtype] = append(typeGroups[qtype], rr)
		}
	}
	for qtype, records := range typeGroups {
		r.cache.Set(zone, qtype, dns.ClassINET, nil, false, records, nil, nil, false, cache.SetOptions{})
	}

	// Store latency in ip_latency for probed IPs.
	for ipStr, lat := range latencies {
		if addr, ok := ipToAddr[ipStr]; ok {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				continue
			}
			cleanIP := net.ParseIP(strings.Trim(host, "[]"))
			if cleanIP != nil {
				qtype := uint16(dns.TypeAAAA)
				if cleanIP.To4() != nil {
					qtype = dns.TypeA
				}
				r.cache.UpdateLatency(zone, qtype, dns.ClassINET, nil, false, cleanIP.String(), lat)
			}
		}
	}
}

// getRootServers returns root servers ordered by probe latency.
// Uses per-type TypeA/TypeAAAA entries; sortAnswerByLatency reorders
// records via ip_latency at Get() time. On cold start, fires a background
// probe and returns shuffled static addresses.
func (r *Recursive) getRootServers() []string {
	if r == nil {
		return DefaultRootServers
	}

	// Look up per-type entries. sortAnswerByLatency reorders by ip_latency.
	aAddrs := lookupCachedRRs(r.cache, ".", dns.TypeA)
	aaaaAddrs := lookupCachedRRs(r.cache, ".", dns.TypeAAAA)
	addrs := make([]string, 0, len(aAddrs)+len(aaaaAddrs))
	addrs = append(addrs, aAddrs...)
	addrs = append(addrs, aaaaAddrs...)
	if len(addrs) > 0 {
		return addrs
	}

	// Cold start: probe in background, return shuffled defaults.
	r.bgGroup.Go(func() error {
		log.Debugf("RECURSION: probing root server latency (%d addresses)", len(DefaultRootServers))
		r.probeAndCacheAddrs(".", DefaultRootServers)
		return nil
	})
	return ShuffleSlice(DefaultRootServers)
}

// probeAndCacheNSGlue probes the IP addresses in nsGlue and stores latency
// values in ip_latency. Per-type cache entries are already written by the
// resolution flow (resolveNSAddressesConcurrent / glue caching) before this
// is called; sortAnswerByLatency reorders them at Get() time via ip_latency.
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

	// Extract IPs from addresses.
	ips := make([]net.IP, 0, len(allAddrs))
	for _, addr := range allAddrs {
		if ip := ipFromAddr(addr); ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
			ips = append(ips, ip)
		}
	}
	if len(ips) <= 1 {
		return
	}

	_, latencies := probe.SortIPsByLatencyMap(probeCtx, ips)
	if len(latencies) == 0 {
		return
	}

	// Store latency values in ip_latency with actual qtype.
	// Per-type entries already exist from the resolution path;
	// sortAnswerByLatency will reorder them at Get() time.
	for nsName, records := range nsGlue {
		for _, rrec := range records {
			if ip, ok := dnsutil.ExtractIPString(rrec); ok {
				if lat, ok := latencies[ip]; ok {
					qtype := dns.RRToType(rrec)
					r.cache.UpdateLatency(nsName, qtype, dns.ClassINET, nil, false, ip, lat)
				}
			}
		}
	}
	log.Debugf("RECURSION: probed %d NS addresses (%d latency values)", len(ips), len(latencies))
}

// lookupNSAddrsFromCache looks up latency-sorted NS addresses via per-type
// TypeA/TypeAAAA entries. sortAnswerByLatency reorders records via ip_latency
// at Get() time, so the returned addresses are already latency-sorted.
func (r *Recursive) lookupNSAddrsFromCache(nsName string) []string {
	if r == nil || r.cache == nil {
		return nil
	}

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
