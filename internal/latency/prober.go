// Package latency provides a unified network latency probing engine for IP
// addresses, used by both the client-facing A/AAAA reorder logic and the
// infrastructure-level root/NS server ordering.
package latency

import (
	"context"
	"math"
	"math/rand/v2"
	"net"
	"sort"
	"sync"
	"time"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

// Prober measures network latency to IP addresses using configurable probe
// steps and returns them sorted fastest-first.
type Prober struct {
	steps    []config.LatencyProbeStep
	sem      chan struct{}
	dedup    *DedupCache
	httpPool *httpClientPool
	ctx      context.Context
}

// New creates a Prober with the given probe steps and background context.
// The context is used for all background probe goroutines and is cancelled
// on server shutdown.
func New(steps []config.LatencyProbeStep, bgCtx context.Context) *Prober {
	if bgCtx == nil {
		bgCtx = context.Background()
	}
	p := &Prober{
		steps:    normalizeSteps(steps),
		sem:      make(chan struct{}, config.DefaultMaxProbes),
		dedup:    NewDedupCache(),
		httpPool: newHTTPClientPool(),
		ctx:      bgCtx,
	}
	return p
}

// normalizeSteps pre-processes probe steps to avoid repeated string operations
// on the hot path.
func normalizeSteps(steps []config.LatencyProbeStep) []config.LatencyProbeStep {
	if len(steps) == 0 {
		return nil
	}
	normalized := make([]config.LatencyProbeStep, len(steps))
	for i, s := range steps {
		s.Protocol = normalizeProbeProtocol(s.Protocol)
		normalized[i] = s
	}
	return normalized
}

// ProbeIPs probes the given IP addresses and returns them sorted by measured
// latency (fastest first). IPs that cannot be probed (loopback, private,
// link-local) are placed at the end in original order. Returns the input
// unmodified when there are 0-1 IPs or no probe steps configured.
func (p *Prober) ProbeIPs(ctx context.Context, ips []net.IP) []net.IP {
	if p == nil || len(ips) <= 1 || len(p.steps) == 0 {
		return ips
	}

	type candidate struct {
		ip      net.IP
		latency time.Duration
	}

	candidates := make([]candidate, len(ips))
	for i, ip := range ips {
		candidates[i] = candidate{ip: ip, latency: time.Duration(math.MaxInt64)}
	}

	sorted, _ := probeSlice(ctx, p.sem, p.ctx, candidates, func(c *candidate) net.IP { return c.ip },
		p.steps, p.httpPool)

	result := make([]net.IP, len(sorted))
	for i, c := range sorted {
		result[i] = c.ip
	}
	return result
}

// ProbeAddrs probes the given "ip:port" address strings and returns them
// sorted by measured latency. Addresses without valid, public IPs are placed
// at the end in original order.
func (p *Prober) ProbeAddrs(ctx context.Context, addrs []string) []net.IP {
	if p == nil || len(addrs) <= 1 || len(p.steps) == 0 {
		ips := make([]net.IP, len(addrs))
		for i, a := range addrs {
			if host, _, err := net.SplitHostPort(a); err == nil {
				ips[i] = net.ParseIP(host)
			}
		}
		return ips
	}

	probeIPs := make([]net.IP, 0, len(addrs))

	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		if ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
			probeIPs = append(probeIPs, ip)
		}
	}

	if len(probeIPs) <= 1 {
		ips := make([]net.IP, len(addrs))
		for i, a := range addrs {
			if h, _, e := net.SplitHostPort(a); e == nil {
				ips[i] = net.ParseIP(h)
			}
		}
		return ips
	}

	// Check dedup cache — skip probe if we recently probed this exact set.
	hash := hashIPs(probeIPs)
	if cached, ok := p.dedup.Get(hash); ok {
		log.Debugf("LATENCY: dedup hit for %d IPs (hash=%x)", len(probeIPs), hash)
		return cached
	}

	sortedIPs := p.ProbeIPs(ctx, probeIPs)
	p.dedup.Set(hash, sortedIPs, dedupTTL)

	return sortedIPs
}

// probeSlice is the generic probe-and-sort core. It spawns concurrent workers
// bounded by the semaphore, measures latency for each item, and returns items
// sorted by latency. All workers respect ctx and bgCtx cancellation.
func probeSlice[T any](
	ctx context.Context,
	sem chan struct{},
	bgCtx context.Context,
	items []T,
	extractIP func(*T) net.IP,
	steps []config.LatencyProbeStep,
	httpPool *httpClientPool,
) ([]T, bool) {

	type candidate struct {
		idx     int
		latency time.Duration
	}

	n := len(items)
	results := make([]candidate, n)
	for i := range results {
		results[i] = candidate{idx: i, latency: time.Duration(math.MaxInt64)}
	}

	// Launch one goroutine per item, bounded by the semaphore.
	var wg sync.WaitGroup
	for i := range items {
		idx := i
		wg.Add(1)
		go func() {
			defer dnsutil.HandlePanic("latency probe worker")
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			case <-bgCtx.Done():
				return
			}
			defer func() { <-sem }()

			latency := measureIPLatency(ctx, bgCtx, extractIP(&items[idx]), steps, httpPool)
			results[idx].latency = latency
		}()
	}
	wg.Wait()

	// Check if any probe succeeded.
	changed := false
	for _, r := range results {
		if r.latency != time.Duration(math.MaxInt64) {
			changed = true
			break
		}
	}
	if !changed {
		return items, false
	}

	// Sort items by probed latency.
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].latency < results[j].latency
	})

	sorted := make([]T, n)
	for i, r := range results {
		sorted[i] = items[r.idx]
	}

	// Log results.
	for _, c := range sorted {
		ip := extractIP(&c)
		if ip != nil {
			for _, r := range results {
				if extractIP(&sorted[r.idx]) != nil && extractIP(&sorted[r.idx]).Equal(ip) {
					log.Debugf("LATENCY: probe result %s latency=%s", ip.String(), r.latency)
					break
				}
			}
		}
	}

	return sorted, true
}

// hashIPs produces a quick, non-cryptographic fingerprint for dedup.
func hashIPs(ips []net.IP) uint64 {
	var h uint64 = 14695981039346656037 // FNV offset basis
	for _, ip := range ips {
		for _, b := range ip {
			h ^= uint64(b)
			h *= 1099511628211 // FNV prime
		}
	}
	// Mix in the length to distinguish [a,b] from [a,b,c].
	h ^= uint64(len(ips)) << 32
	return h
}

// normalizeProbeProtocol canonicalizes protocol names (e.g. "ICMP" → "ping").
func normalizeProbeProtocol(p string) string {
	switch p {
	case "icmp", "ICMP":
		return "ping"
	default:
		return p
	}
}

// ShuffleIPs returns a shuffled copy using crypto/rand for unbiased ordering.
func ShuffleIPs(ips []net.IP) []net.IP {
	if len(ips) <= 1 {
		return ips
	}
	shuffled := make([]net.IP, len(ips))
	copy(shuffled, ips)
	for i := len(shuffled) - 1; i > 0; i-- {
		j := rand.IntN(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	return shuffled
}
