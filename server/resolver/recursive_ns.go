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
	if r.cache != nil {
		for _, ns := range bestNSRecords {
			nsName := dnsutil.Fqdn(ns.Ns)
			cached := r.lookupNSAddrsFromCache(nsName, nil)
			if len(cached) > 0 {
				result.addrs = append(result.addrs, cached...)
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

	// Fall back to glue records when cache doesn't cover all NS names.
	result.glue = make(map[string][]dns.RR) // NS name → A/AAAA glue records
	if len(result.addrs) == 0 {
		for _, ns := range bestNSRecords {
			for _, rrec := range response.Extra {
				ip, ok := extractGlueIP(rrec, ns.Ns)
				if !ok {
					continue
				}
				rrecName := zdnsutil.NormalizeDomain(rrec.Header().Name)
				parDom := zdnsutil.NormalizeDomain(parentDomain)
				if rrecName != parDom && !strings.HasSuffix(rrecName, "."+parDom) && parDom != "" {
					continue
				}
				nsKey := dnsutil.Fqdn(rrec.Header().Name)
				result.glue[nsKey] = append(result.glue[nsKey], rrec)
				result.addrs = append(result.addrs, net.JoinHostPort(ip, config.DefaultUDPPort))
			}
		}
	}

	// Use glue records directly when available; only fall back to independent
	// NS resolution when the delegation has no glue.
	if len(result.addrs) == 0 {
		result.addrs = r.resolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth, forceTCP)
		if len(result.addrs) > 0 {
			result.source = "resolution"
		}
	} else if result.source == "" {
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
		if len(records) > 0 {
			qtype := dns.RRToType(records[0])
			r.cache.Set(nsName, qtype, dns.ClassINET, nil, false, records, nil, nil, false)
		}
	}
	for _, records := range glue {
		addrs := addrsFromRRs(records)
		go probe.ProbeNSAddrs(r.ctx, r.cache, addrs)
	}
}
