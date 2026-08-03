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
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

// Prober measures network latency to IP addresses using configurable probe
// steps and returns them sorted fastest-first.
type Prober struct {
	steps     []config.LatencyProbeStep
	sem       chan struct{}
	httpPool  *httpClientPool
	ctx       context.Context
	closeOnce sync.Once
	probeMu   sync.Mutex // guards closed + probeWg.Add vs Close's Wait
	probeWg   sync.WaitGroup
	closed    bool
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

// Close releases resources held by the prober (HTTP/3 QUIC connections).
// The prober must not be used after Close is called.
func (p *Prober) Close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		// Drain in-flight probes first: closing the pooled transports under
		// them would fail their requests and free sockets out from under
		// them. Probes are bounded by step timeouts, so this cannot block
		// indefinitely. Setting closed first (under the mutex) prevents new
		// ProbeIPsLatency calls from registering workers while we wait.
		p.probeMu.Lock()
		p.closed = true
		p.probeMu.Unlock()
		p.probeWg.Wait()
		if p.httpPool != nil {
			p.httpPool.Close()
		}
	})
}

// ProbeIPsLatency probes the given IP addresses and returns them sorted by
// measured latency along with a map of IP → latency in milliseconds.
func (p *Prober) ProbeIPsLatency(ctx context.Context, ips []net.IP) (sorted []net.IP, latencyMS map[string]int) {
	if p == nil || len(ips) <= 1 || len(p.steps) == 0 {
		return ips, nil
	}
	if ctx == nil {
		// measureIPLatency derives step contexts via WithTimeout — a nil ctx
		// would panic there. Defensive, mirroring New's bgCtx nil guard.
		ctx = context.Background()
	}

	n := len(ips)

	type result struct {
		idx     int
		latency time.Duration
	}

	results := make([]result, n)
	for i := range results {
		results[i] = result{idx: i, latency: time.Duration(math.MaxInt64)}
	}

	// Bounded worker pool — at most cap(p.sem) workers with jobs dispatched
	// over a channel. One goroutine per IP would spawn N goroutines for N
	// nameservers; the worker pool caps concurrency at the probe limit.
	workers := min(n, cap(p.sem))
	if workers <= 0 {
		workers = 1
	}
	// Register BEFORE starting workers; Close() waits on this group only
	// after setting closed, and the mutex makes Add/Wait mutually exclusive
	// so a concurrent Close cannot race a zero-count Add. probeWg is
	// lifecycle-only: waiting for THIS call's workers uses callWg below,
	// because ProbeIPsLatency calls run concurrently (one per probe key)
	// and a shared WaitGroup's Wait must never overlap another call's Add.
	p.probeMu.Lock()
	if p.closed {
		p.probeMu.Unlock()
		return ips, nil
	}
	p.probeWg.Add(workers)
	p.probeMu.Unlock()

	var callWg sync.WaitGroup
	callWg.Add(workers)

	jobs := make(chan int)
	for range workers {
		go func() {
			defer zdnsutil.HandlePanic("latency probe worker")
			defer p.probeWg.Done()
			defer callWg.Done()
			for idx := range jobs {
				// The semaphore is SHARED across all ProbeIPsLatency calls:
				// concurrent probes of different NS sets stay within the
				// global concurrency budget. Release via defer so a worker
				// panic (recovered by HandlePanic) cannot leak the slot —
				// a leaked slot would permanently shrink the budget.
				select {
				case p.sem <- struct{}{}:
					func() {
						defer func() { <-p.sem }()
						results[idx].latency = measureIPLatency(ctx, ips[idx], p.steps, p.httpPool)
					}()
				case <-p.ctx.Done():
					return
				}
			}
		}()
	}
sendJobs:
	for i := range ips {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break sendJobs
		case <-p.ctx.Done():
			break sendJobs
		}
	}
	close(jobs)
	callWg.Wait()

	changed := false
	latencyMS = make(map[string]int, n)
	for _, r := range results {
		if r.latency != time.Duration(math.MaxInt64) {
			changed = true
			latencyMS[ips[r.idx].String()] = int(r.latency / time.Millisecond)
		}
	}
	if !changed {
		return ips, nil
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

	sorted = make([]net.IP, n)
	for i, r := range results {
		sorted[i] = ips[r.idx]
		log.Debugf("LATENCY: probe result %s latency=%s", sorted[i].String(), r.latency)
	}

	return sorted, latencyMS
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

// normalizeProbeProtocol canonicalizes protocol names (e.g. "ICMP" → "ping").
func normalizeProbeProtocol(p string) string {
	switch p {
	case "icmp", "ICMP":
		return "ping"
	default:
		return p
	}
}
