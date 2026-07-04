// Package latency provides a unified network latency probing engine for IP
// addresses, used by both the client-facing A/AAAA reorder logic and the
// infrastructure-level root/NS server ordering.
package latency

import (
	"context"
	"math"
	"net"
	"slices"
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
	sorted, _, _ := p.probeIPs(ctx, ips)
	return sorted
}

// ProbeIPsLatency probes the given IP addresses and returns them sorted by
// measured latency along with a map of IP → latency in milliseconds.
func (p *Prober) ProbeIPsLatency(ctx context.Context, ips []net.IP) ([]net.IP, map[string]int) {
	if p == nil || len(ips) <= 1 || len(p.steps) == 0 {
		return ips, nil
	}

	sorted, latencies, changed := p.probeIPs(ctx, ips)
	if !changed {
		return ips, nil
	}

	latencyMS := make(map[string]int, len(sorted))
	for ip, lat := range latencies {
		latencyMS[ip] = int(lat / time.Millisecond)
	}
	return sorted, latencyMS
}

// probeIPs is the probe-and-sort core. It spawns concurrent workers bounded
// by the semaphore, measures latency for each IP, and returns them sorted
// fastest-first. All workers respect ctx and bgCtx cancellation.
func (p *Prober) probeIPs(ctx context.Context, ips []net.IP) ([]net.IP, map[string]time.Duration, bool) {
	n := len(ips)

	type result struct {
		idx     int
		latency time.Duration
	}

	results := make([]result, n)
	for i := range results {
		results[i] = result{idx: i, latency: time.Duration(math.MaxInt64)}
	}

	var wg sync.WaitGroup
	for i := range ips {
		idx := i
		wg.Add(1)
		go func() {
			defer dnsutil.HandlePanic("latency probe worker")
			defer wg.Done()

			select {
			case p.sem <- struct{}{}:
			case <-ctx.Done():
				return
			case <-p.ctx.Done():
				return
			}
			defer func() { <-p.sem }()

			results[idx].latency = measureIPLatency(ctx, p.ctx, ips[idx], p.steps, p.httpPool)
		}()
	}
	wg.Wait()

	changed := false
	latencies := make(map[string]time.Duration, n)
	for _, r := range results {
		if r.latency != time.Duration(math.MaxInt64) {
			changed = true
			latencies[ips[r.idx].String()] = r.latency
		}
	}
	if !changed {
		return ips, nil, false
	}

	slices.SortStableFunc(results, func(a, b result) int {
		if a.latency < b.latency {
			return -1
		}
		if a.latency > b.latency {
			return 1
		}
		return 0
	})

	sorted := make([]net.IP, n)
	for i, r := range results {
		sorted[i] = ips[r.idx]
		log.Debugf("LATENCY: probe result %s latency=%s", sorted[i].String(), r.latency)
	}

	return sorted, latencies, true
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
