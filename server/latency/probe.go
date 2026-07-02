// Package latency provides A/AAAA latency probing and record reordering for
// optimized client connectivity.
package latency

import (
	"context"
	"net"
	"sync"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	ilatency "zjdns/internal/latency"
	"zjdns/internal/log"
)

// CacheSetter is the interface for updating the DNS cache with reordered
// records after latency probing.
type CacheSetter interface {
	Set(cacheKey string, answer, authority, additional []dns.RR, validated bool, ecs *edns.ECSOption)
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
func (p *Prober) Start(question dns.Question, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *edns.ECSOption) {
	if p == nil || p.engine == nil {
		log.Debugf("LATENCY: probe skipped for %s because latency_probe is not configured", question.Name)
		return
	}
	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		log.Debugf("LATENCY: probe skipped for %s because query type is not A/AAAA", question.Name)
		return
	}
	if len(answer) <= 1 {
		log.Debugf("LATENCY: probe skipped for %s because answer length <= 1", question.Name)
		return
	}

	var ipRRCount int
	for _, rr := range answer {
		if isAOrAAAA(rr) {
			ipRRCount++
			if ipRRCount > 1 {
				break
			}
		}
	}
	if ipRRCount <= 1 {
		log.Debugf("LATENCY: probe skipped for %s because only one A/AAAA record present", question.Name)
		return
	}

	log.Debugf("LATENCY: starting background latency probe for %s", question.Name)

	p.bgGroup(func() error {
		defer dnsutil.HandlePanic("latency probe")
		if err := p.probeAndReorder(p.bgCtx, cacheKey, answer, authority, additional, validated, ecsResponse); err != nil {
			log.Debugf("LATENCY: background probe failed for %s: %v", question.Name, err)
		}
		return nil
	})
}

func (p *Prober) probeAndReorder(ctx context.Context, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *edns.ECSOption) error {
	if ctx == nil {
		ctx = context.Background()
	}

	log.Debugf("LATENCY: performing latency probe for cache key %s", cacheKey)

	// Extract IPs from A/AAAA records.
	type indexedRecord struct {
		idx int
		rr  dns.RR
		ip  net.IP
	}
	records := make([]indexedRecord, 0, len(answer))
	for i, rr := range answer {
		if ip := dnsutil.ExtractIP(rr); ip != nil {
			records = append(records, indexedRecord{idx: i, rr: rr, ip: ip})
		}
	}
	if len(records) <= 1 {
		log.Debugf("LATENCY: no multiple probeable IPs for %s", cacheKey)
		return nil
	}

	ips := make([]net.IP, len(records))
	for i, r := range records {
		ips[i] = r.ip
	}

	sortedIPs := p.engine.ProbeIPs(ctx, ips)

	// Build sorted answer, preserving non-A/AAAA records at original positions.
	sortedAnswer := make([]dns.RR, len(answer))
	copy(sortedAnswer, answer)

	// Map IP back to original record.
	ipToRR := make(map[string]dns.RR, len(records))
	for _, r := range records {
		ipToRR[r.ip.String()] = r.rr
	}

	pos := 0
	changed := false
	for _, idx := range extractIndices(answer) {
		if pos < len(sortedIPs) {
			sortedAnswer[idx] = ipToRR[sortedIPs[pos].String()]
			if sortedAnswer[idx].String() != answer[idx].String() {
				changed = true
			}
			pos++
		}
	}

	if !changed {
		log.Debugf("LATENCY: no faster A/AAAA order found for %s", cacheKey)
		return nil
	}

	p.cache.Set(cacheKey, sortedAnswer, authority, additional, validated, ecsResponse)
	log.Debugf("LATENCY: reordered A/AAAA records for %s", cacheKey)
	return nil
}

// extractIndices returns the indices of A/AAAA records in the answer slice.
func extractIndices(answer []dns.RR) []int {
	indices := make([]int, 0, len(answer))
	for i, rr := range answer {
		if isAOrAAAA(rr) {
			indices = append(indices, i)
		}
	}
	return indices
}

// --- Infrastructure-level API (used by resolver for root/NS server ordering) ---

// infraProber holds the package-level prober for infrastructure (root/NS)
// latency probes. Protected by infraProberOnce for safe concurrent initialization.
var (
	infraProber     *ilatency.Prober
	infraProberOnce sync.Once
)

// NewInfraProber initializes the package-level infrastructure prober.
// Safe to call multiple times; only the first call takes effect.
func NewInfraProber(bgCtx context.Context) {
	infraProberOnce.Do(func() {
		infraProber = ilatency.New([]config.LatencyProbeStep{
			{Protocol: config.ProtoPing, Timeout: 100},
			{Protocol: config.ProtoUDP, Port: config.DefaultProbePortDNS, Timeout: 100},
			{Protocol: config.ProtoTCP, Port: config.DefaultProbePortDNS, Timeout: 100},
		}, bgCtx)
	})
}

// SortIPsByLatency probes IP addresses using the built-in infrastructure
// probe steps and returns them sorted by measured latency (fastest first).
// IPs that cannot be probed (loopback, private, link-local) are placed at
// the end. Uses the package-level infrastructure prober.
func SortIPsByLatency(ctx context.Context, ips []net.IP) []net.IP {
	if infraProber == nil {
		return ips
	}
	return infraProber.ProbeIPs(ctx, ips)
}

// --- Shared helpers ---

func isAOrAAAA(rr dns.RR) bool {
	if rr == nil {
		return false
	}
	rtype := rr.Header().Rrtype
	return rtype == dns.TypeA || rtype == dns.TypeAAAA
}
