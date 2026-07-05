package resolver

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"codeberg.org/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/dnsutil"
	ilatency "zjdns/internal/latency"
)

// ── Latency-sorted NS address cache ──────────────────────────────────────────
//
// Root servers and per-nameserver addresses are stored as regular TypeA/TypeAAAA
// cache entries by the resolution flow (or seedRootCache for root servers).
// probeNSAddrs runs background latency probes and stores results in ip_latency;
// sortAnswerByLatency in cache.Get() reorders records at read time.
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

// ipFromAddr extracts the net.IP from an "ip:port" string.
func ipFromAddr(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

// defaultNSProbeSteps returns the default probe steps for NS/Root latency
// probing (ping → UDP:53 → TCP:53, 100ms each). Mirrors the infra prober
// steps that were previously hardcoded in server/probe/probe.go.
func defaultNSProbeSteps() []config.LatencyProbeStep {
	return []config.LatencyProbeStep{
		{Protocol: config.ProtoPing, Timeout: 100},
		{Protocol: config.ProtoUDP, Port: config.DefaultProbePortDNS, Timeout: 100},
		{Protocol: config.ProtoTCP, Port: config.DefaultProbePortDNS, Timeout: 100},
	}
}

// probeNSAddrs probes the given "ip:port" addresses and stores latency
// values in ip_latency with the actual qtype. Does NOT write cache entries —
// those are written by the resolution flow (NS) or seedRootCache (root).
func (r *Recursive) probeNSAddrs(zone string, addrs []string) {
	defer dnsutil.HandlePanic("probeNSAddrs")
	if len(addrs) <= 1 || r.cache == nil {
		return
	}

	// Extract public IPs.
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

	prober := ilatency.New(defaultNSProbeSteps(), nil)
	probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, latencies := prober.ProbeIPsLatency(probeCtx, ips)
	if len(latencies) == 0 {
		return
	}

	for ipStr, lat := range latencies {
		addr, ok := ipToAddr[ipStr]
		if !ok {
			continue
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		cleanIP := net.ParseIP(strings.Trim(host, "[]"))
		if cleanIP == nil {
			continue
		}
		qtype := uint16(dns.TypeAAAA)
		if cleanIP.To4() != nil {
			qtype = dns.TypeA
		}
		r.cache.UpdateLatency(zone, qtype, dns.ClassINET, nil, false, cleanIP.String(), lat)
	}
}

// cacheRootServers writes the static root server list as TypeA/TypeAAAA
// entries so getRootServers() can use the normal cache.Get() path.
func (r *Recursive) cacheRootServers() {
	typeGroups := make(map[uint16][]dns.RR)
	for _, addr := range DefaultRootServers {
		if rr := addrToRR(".", addr, 3600); rr != nil {
			qtype := dns.RRToType(rr)
			typeGroups[qtype] = append(typeGroups[qtype], rr)
		}
	}
	for qtype, records := range typeGroups {
		r.cache.Set(".", qtype, dns.ClassINET, nil, false, records, nil, nil, false, cache.SetOptions{})
	}
}

// getRootServers returns root servers ordered by probe latency.
func (r *Recursive) getRootServers() []string {
	if r == nil {
		return DefaultRootServers
	}

	aAddrs := lookupCachedRRs(r.cache, ".", dns.TypeA)
	aaaaAddrs := lookupCachedRRs(r.cache, ".", dns.TypeAAAA)
	addrs := append(aAddrs, aaaaAddrs...)

	if len(addrs) == 0 {
		// Cold start: write entries, probe latency, read back.
		r.cacheRootServers()
		go r.probeNSAddrs(".", DefaultRootServers)
		aAddrs = lookupCachedRRs(r.cache, ".", dns.TypeA)
		aaaaAddrs = lookupCachedRRs(r.cache, ".", dns.TypeAAAA)
		addrs = append(aAddrs, aaaaAddrs...)
	}

	if len(addrs) == 0 {
		return DefaultRootServers
	}
	return addrs
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
