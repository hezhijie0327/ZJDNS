// Package probe provides A/AAAA latency probing and record reordering for
// optimized client connectivity.
package probe

import (
	"context"
	"net"
	"strings"
	"time"

	"codeberg.org/miekg/dns"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	ilatency "zjdns/internal/latency"
	"zjdns/internal/log"
)

// CacheSetter is the interface for updating latency measurements in the
// cache after probing.
type CacheSetter interface {
	Set(qname string, qtype, qclass uint16, ecs *edns.ECSOption, dnssecOK bool, answer, authority, additional []dns.RR, validated bool)
	UpdateLatency(ip string, latencyMS int)
	GetLatencyLastProbe(ip string) (int64, bool)
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

// Close releases resources held by the prober (HTTP/3 QUIC connections).
func (p *Prober) Close() {
	if p != nil && p.engine != nil {
		p.engine.Close()
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

	// Skip if all IPs in the answer were recently probed. Each IP is checked
	// individually — CDN IPs shared across domains are deduped globally.
	now := time.Now().Unix()
	allRecent := true
	for _, rr := range answer {
		ip, ok := dnsutil.ExtractIPString(rr)
		if !ok {
			continue
		}
		lastProbe, ok := p.cache.GetLatencyLastProbe(ip)
		if !ok || now-lastProbe >= int64(config.DefaultLatencyProbeMinInterval) {
			allRecent = false
			break
		}
	}
	if allRecent {
		log.Debugf("LATENCY: probe skipped for %s (all IPs recently probed)", qname)
		return
	}

	log.Debugf("LATENCY: starting background latency probe for %s", qname)

	p.bgGroup(func() error {
		defer dnsutil.HandlePanic("latency probe")
		if err := p.probeAndReorder(p.bgCtx, qname, qtype, answer, ecsResponse); err != nil {
			log.Debugf("LATENCY: background probe failed for %s: %v", qname, err)
		}
		return nil
	})
}

func (p *Prober) probeAndReorder(ctx context.Context, qname string, qtype uint16, answer []dns.RR, ecsResponse *edns.ECSOption) error {
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
		p.cache.UpdateLatency(ipStr, lat)
	}
	log.Debugf("LATENCY: updated %d latency values for %s", len(latencies), qname)
	return nil
}

// --- Shared probe function (used by handler prober + resolver NS/Root) ---

// defaultNSProbeSteps returns the default probe steps for NS/Root latency
// probing (ping → UDP:53 → TCP:53).
func defaultNSProbeSteps() []config.LatencyProbeStep {
	return []config.LatencyProbeStep{
		{Protocol: config.ProtoPing, Timeout: 100},
		{Protocol: config.ProtoUDP, Port: config.DefaultProbePortDNS, Timeout: 100},
		{Protocol: config.ProtoTCP, Port: config.DefaultProbePortDNS, Timeout: 100},
	}
}

// ProbeNSAddrs probes the given "ip:port" addresses and stores latency values
// in ip_latency. Does NOT write cache entries — the caller is responsible for
// that. Used by the resolver for NS/Root addresses.
func ProbeNSAddrs(cache CacheSetter, addrs []string) {
	if cache == nil || len(addrs) <= 1 {
		return
	}

	// Extract public IPs. Latency is per-IP, not per-domain, so we only
	// need the IP list — no qtype tracking required.
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
			continue
		}
		ips = append(ips, ip)
	}
	if len(ips) <= 1 {
		return
	}

	// Skip IPs that were recently probed.
	now := time.Now().Unix()
	needProbe := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		lastProbe, ok := cache.GetLatencyLastProbe(ip.String())
		if !ok || now-lastProbe >= int64(config.DefaultLatencyProbeMinInterval) {
			needProbe = append(needProbe, ip)
		}
	}
	if len(needProbe) <= 1 {
		return
	}

	prober := ilatency.New(defaultNSProbeSteps(), nil)
	defer prober.Close()
	ctx, cancel := context.WithTimeout(context.Background(), config.DefaultNSProbeTimeout)
	defer cancel()
	_, latencies := prober.ProbeIPsLatency(ctx, needProbe)
	if len(latencies) == 0 {
		return
	}

	for ipStr, lat := range latencies {
		cache.UpdateLatency(ipStr, lat)
	}
}

// --- Shared helpers ---
