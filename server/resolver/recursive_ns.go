package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/server/resolver/probe"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// resolvedNSAddrs holds the result of resolveNextNameservers.
type resolvedNSAddrs struct {
	addrs  []string
	source string // "cache", "glue", or "resolution"
	glue   map[string][]dns.RR
}

// resolveNextNameservers resolves addresses for the nameservers at the next
// delegation level.  It tries cache first (latency-sorted), then glue
// records from the referral response, then falls back to independent NS
// resolution.  Glue records are cached and probed asynchronously.
func (r *Recursive) resolveNextNameservers(
	ctx context.Context,
	bestNSRecords []*dns.NS,
	response *dns.Msg,
	qname, parentDomain string,
	depth int,
	forceTCP bool,
) resolvedNSAddrs {
	var result resolvedNSAddrs

	// Try cache first — latency-sorted records from previous resolutions.
	var cachedNSNames map[string]bool // track NS names satisfied by cache
	if r.cache != nil {
		for _, ns := range bestNSRecords {
			nsName := dnsutil.Fqdn(ns.Ns)
			if cachedNSNames[nsName] {
				continue // duplicate NS target — addresses already appended
			}
			cached := r.lookupNSAddrsFromCache(nsName, nil)
			if len(cached) > 0 {
				result.addrs = append(result.addrs, cached...)
				if cachedNSNames == nil {
					cachedNSNames = make(map[string]bool, len(bestNSRecords))
				}
				cachedNSNames[nsName] = true
				if len(cached) > 1 && log.Default.Level() >= log.Debug {
					rankParts := make([]string, 0, len(cached))
					for i, addr := range cached {
						rankParts = append(rankParts, fmt.Sprintf("#%d=%s", i+1, addr))
					}
					log.Debugf("RECURSION: NS %s cached (sorted): %s", nsName, strings.Join(rankParts, " "))
				}
			}
		}
		if len(result.addrs) > 0 {
			result.source = "cache"
		}
	}

	// Fall back to glue records for NS names not satisfied by cache.
	result.glue = make(map[string][]dns.RR) // NS name → A/AAAA glue records
	fqParDom := dnsutil.Fqdn(parentDomain)
	for _, ns := range bestNSRecords {
		nsName := dnsutil.Fqdn(ns.Ns)
		if cachedNSNames[nsName] {
			continue // already have cached addresses for this NS
		}
		for _, rrec := range response.Extra {
			ip, ok := extractGlueIP(rrec, ns.Ns)
			if !ok {
				continue
			}
			rrecNameFq := dnsutil.Fqdn(rrec.Header().Name)
			// Bailiwick gate: glue is only trusted when its owner shares the
			// parent hierarchy (RFC 1034 §4.3.2) — out-of-bailiwick glue is
			// rejected.  In-bailiwick child-zone glue passes because it is
			// also below the parent (IsBelow(parent, child) is true).
			if !dnsutil.IsBelow(fqParDom, rrecNameFq) && fqParDom != "." {
				continue
			}
			result.glue[rrecNameFq] = append(result.glue[rrecNameFq], rrec)
			result.addrs = append(result.addrs, net.JoinHostPort(ip, config.DefaultUDPPort))
		}
	}

	// Resolve independently any NS names not covered by cache or glue: the
	// old short-circuit dropped the remaining delegation targets whenever
	// cache/glue covered even a subset, so resolution could fail even though
	// the uncovered servers were reachable.
	//
	// In-bailiwick NS names of the zone being entered are skipped when cache
	// and glue both miss: resolving ns1.example.com to enter example.com
	// requires querying example.com's servers — whose addresses are exactly
	// what is being resolved (circular).  The self-name guard in
	// resolveNSAddressesConcurrent breaks the single-NS cycle; this extends
	// it to sibling NS names so walks for ns1/ns2 of the same zone terminate
	// instead of recursing into each other until the depth limit.  Such a
	// delegation is unreachable without glue/cache and now fails with
	// "could not resolve nameservers" instead of deadlocking the walk.
	zone := ""
	if len(bestNSRecords) > 0 {
		zone = dnsutil.Fqdn(bestNSRecords[0].Header().Name)
	}
	uncovered := make([]*dns.NS, 0, len(bestNSRecords))
	for _, ns := range bestNSRecords {
		nsName := dnsutil.Fqdn(ns.Ns)
		if cachedNSNames[nsName] || len(result.glue[nsName]) > 0 {
			continue
		}
		if zone != "" && dnsutil.IsBelow(zone, nsName) {
			log.Debugf("RECURSION: skipping in-bailiwick NS %s for %s (no glue/cache — circular)", nsName, zone)
			continue
		}
		uncovered = append(uncovered, ns)
	}
	if len(uncovered) > 0 {
		resolved := r.resolveNSAddressesConcurrent(ctx, uncovered, qname, depth, forceTCP)
		if len(resolved) > 0 {
			result.addrs = append(result.addrs, resolved...)
			if result.source == "" {
				result.source = "resolution"
			}
		}
	}
	if result.source == "" && len(result.addrs) > 0 {
		result.source = "glue"
	}

	return result
}

// cacheGlueRecords stores glue A/AAAA records per NS name and fires
// background latency probes.  Must be called with a non-nil cache.
func (r *Recursive) cacheGlueRecords(glue map[string][]dns.RR) {
	if r.cache == nil || len(glue) == 0 {
		return
	}
	for nsName, records := range glue {
		var aGlue, aaaaGlue []dns.RR
		for _, rec := range records {
			switch rec.(type) {
			case *dns.A:
				aGlue = append(aGlue, rec)
			case *dns.AAAA:
				aaaaGlue = append(aaaaGlue, rec)
			}
		}
		if len(aGlue) > 0 {
			r.cache.Set(nsName, dns.TypeA, dns.ClassINET, nil, false, aGlue, nil, nil, false, 0)
		}
		if len(aaaaGlue) > 0 {
			r.cache.Set(nsName, dns.TypeAAAA, dns.ClassINET, nil, false, aaaaGlue, nil, nil, false, 0)
		}
	}
	for _, records := range glue {
		addrs := addrsFromRRs(records)
		if probe.TryProbeNSAddrs(r.cache, addrs) {
			go func() { defer zdnsutil.HandlePanic("NS addr probe"); probe.ProbeNSAddrs(r.ctx, r.cache, addrs) }()
		}
	}
}
