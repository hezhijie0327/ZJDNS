// Package probe provides A/AAAA latency probing and record reordering for
// optimized client connectivity.
package probe

import (
	"context"
	"net"

	"codeberg.org/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	ilatency "zjdns/internal/latency"
	"zjdns/internal/log"
)

// CacheSetter is the interface for updating latency measurements in the
// cache after probing.
type CacheSetter interface {
	Set(qname string, qtype, qclass uint16, ecs *edns.ECSOption, dnssecOK bool, answer, authority, additional []dns.RR, validated bool, opts cache.SetOptions)
	UpdateLatency(qname string, qtype, qclass uint16, ecs *edns.ECSOption, dnssecOK bool, ip string, latencyMS int)
}

// Prober measures network latency to resolved IP addresses and reorders A/AAAA
// records in the cache to prioritize faster endpoints.
type Prober struct {
	cache   CacheSetter
	bgGroup func(func() error)
	bgCtx   context.Context
	engine  *ilatency.Prober
}

// New creates a new Prober with the given cache setter, background group
// executor, context, and probe configuration steps.
func New(cache CacheSetter, bgGroup func(func() error), bgCtx context.Context, steps []config.LatencyProbeStep) *Prober {
	return &Prober{
		cache:   cache,
		bgGroup: bgGroup,
		bgCtx:   bgCtx,
		engine:  ilatency.New(steps, bgCtx),
	}
}

// Start initiates a background latency probe for A/AAAA records when multiple
// addresses exist. If probing finds a faster ordering, the cache is updated.
func (p *Prober) Start(qname string, qtype uint16, answer, authority, additional []dns.RR, validated bool, ecsResponse *edns.ECSOption) {
	if p == nil || p.engine == nil {
		log.Debugf("LATENCY: probe skipped for %s because latency_probe is not configured", qname)
		return
	}
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		log.Debugf("LATENCY: probe skipped for %s because query type is not A/AAAA", qname)
		return
	}
	if len(answer) <= 1 {
		log.Debugf("LATENCY: probe skipped for %s because answer length <= 1", qname)
		return
	}

	var ipRRCount int
	for _, rr := range answer {
		if dnsutil.IsAOrAAAA(rr) {
			ipRRCount++
			if ipRRCount > 1 {
				break
			}
		}
	}
	if ipRRCount <= 1 {
		log.Debugf("LATENCY: probe skipped for %s because only one A/AAAA record present", qname)
		return
	}

	log.Debugf("LATENCY: starting background latency probe for %s", qname)

	p.bgGroup(func() error {
		defer dnsutil.HandlePanic("latency probe")
		if err := p.probeAndReorder(p.bgCtx, qname, qtype, answer, authority, additional, validated, ecsResponse); err != nil {
			log.Debugf("LATENCY: background probe failed for %s: %v", qname, err)
		}
		return nil
	})
}

func (p *Prober) probeAndReorder(ctx context.Context, qname string, qtype uint16, answer, authority, additional []dns.RR, validated bool, ecsResponse *edns.ECSOption) error {
	if ctx == nil {
		ctx = context.Background()
	}

	log.Debugf("LATENCY: performing latency probe for %s", qname)

	// Extract IPs from A/AAAA records.
	ips := make([]net.IP, 0, len(answer))
	for _, rr := range answer {
		if ip := dnsutil.ExtractIP(rr); ip != nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) <= 1 {
		log.Debugf("LATENCY: no multiple probeable IPs for %s", qname)
		return nil
	}

	_, latencies := p.engine.ProbeIPsLatency(ctx, ips)
	if len(latencies) == 0 {
		log.Debugf("LATENCY: all probes failed for %s", qname)
		return nil
	}

	for ipStr, lat := range latencies {
		p.cache.UpdateLatency(qname, qtype, dns.ClassINET, ecsResponse, false, ipStr, lat)
	}
	log.Debugf("LATENCY: updated %d latency values for %s", len(latencies), qname)
	return nil
}

// --- Shared helpers ---
