package probe

import (
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
