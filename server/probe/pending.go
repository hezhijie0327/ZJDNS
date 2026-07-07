package probe

import (
	"net"
	"slices"
	"strings"
	"sync"

	"zjdns/internal/log"
)

// probeKey identifies a unique in-flight latency probe.
type probeKey struct {
	qname string
	qtype uint16
}

// PendingProbes deduplicates concurrent latency probes for the same domain.
// When Start() is called for a qname+qtype that already has a probe in flight,
// the call is silently dropped — no duplicate probe is spawned.
type PendingProbes struct {
	mu   sync.Mutex
	sets map[probeKey]chan struct{}
}

// NewPendingProbes creates a PendingProbes ready for use.
func NewPendingProbes() *PendingProbes {
	return &PendingProbes{
		sets: make(map[probeKey]chan struct{}),
	}
}

// Start returns true if the caller should proceed with probing (leader).
// Returns false if a probe for this key is already in flight (follower —
// no need to start another).
func (p *PendingProbes) Start(qname string, qtype uint16) bool {
	key := probeKey{qname: qname, qtype: qtype}

	p.mu.Lock()
	_, loaded := p.sets[key]
	if loaded {
		p.mu.Unlock()
		log.Debugf("LATENCY: probe skipped for %s (type=%d) — already in flight", qname, qtype)
		return false
	}
	p.sets[key] = make(chan struct{})
	p.mu.Unlock()
	return true
}

// Done removes the pending probe key after the probe completes, allowing
// future probes for the same qname+qtype to proceed.
func (p *PendingProbes) Done(qname string, qtype uint16) {
	key := probeKey{qname: qname, qtype: qtype}

	p.mu.Lock()
	ch, ok := p.sets[key]
	if !ok {
		p.mu.Unlock()
		return
	}
	delete(p.sets, key)
	p.mu.Unlock()

	close(ch)
}

// --- Package-level dedup for ProbeNSAddrs (keyed by sorted IP set) ---

var (
	nsProbeMu   sync.Mutex
	nsProbeSets = make(map[string]chan struct{})
)

// tryStartNSProbe attempts to register an NS probe for the given IP set key.
// Returns true if the caller should proceed. The key must be a deterministic,
// sorted representation of the IPs to probe.
func tryStartNSProbe(key string) bool {
	nsProbeMu.Lock()
	_, loaded := nsProbeSets[key]
	if loaded {
		nsProbeMu.Unlock()
		return false
	}
	nsProbeSets[key] = make(chan struct{})
	nsProbeMu.Unlock()
	return true
}

// finishNSProbe removes the pending NS probe key after the probe completes.
func finishNSProbe(key string) {
	nsProbeMu.Lock()
	ch, ok := nsProbeSets[key]
	if !ok {
		nsProbeMu.Unlock()
		return
	}
	delete(nsProbeSets, key)
	nsProbeMu.Unlock()
	close(ch)
}

// buildNSProbeKey returns a deterministic string key from a sorted IP list.
func buildNSProbeKey(ips []net.IP) string {
	strs := make([]string, len(ips))
	for i, ip := range ips {
		strs[i] = ip.String()
	}
	slices.Sort(strs)
	return strings.Join(strs, ",")
}
