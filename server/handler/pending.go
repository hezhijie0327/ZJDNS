package handler

import (
	"errors"
	"sync"
	"time"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pending"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
)

// --- Exported type ---

// PendingRequests deduplicates concurrent identical queries.  When multiple
// clients query the same name+type+ECS before the result is cached, only the
// first query (leader) is sent upstream.  Followers block until the leader
// completes, then receive the same result.  This reduces upstream load and
// closes the window for cache-poisoning attacks that exploit concurrent
// identical queries.
type PendingRequests struct {
	mu   sync.Mutex
	sets map[PendingKey]*pendingCall
}

// --- Unexported types ---

// PendingKey is a pre-computed cache key for deduplicating concurrent identical
// queries.  It mirrors the cache lookup key (qname, qtype, qclass, ecs_addr,
// ecs_prefix, dnssec_ok).
type PendingKey struct {
	qname     string
	qtype     uint16
	qclass    uint16
	ecsAddr   string
	ecsPrefix uint8
	dnssecOK  bool
}

// pendingCall tracks one in-flight upstream query and broadcasts its result to
// all waiting callers.
type pendingCall struct {
	done   chan struct{}
	result *resolver.QueryResult
}

const maxPendingEntries = 10000 // safety bound against unbounded growth

// NewPendingRequests creates a PendingRequests ready for use.
func NewPendingRequests() *PendingRequests {
	p := &PendingRequests{
		sets: make(map[PendingKey]*pendingCall),
	}
	// Periodic cleanup of orphaned entries from panicked/broken leaders.
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			p.mu.Lock()
			if len(p.sets) > maxPendingEntries {
				n := 0
				for k := range p.sets {
					delete(p.sets, k)
					n++
					if n >= len(p.sets)/2 {
						break
					}
				}
			}
			p.mu.Unlock()
		}
	}()
	return p
}

// NewRefreshGroup creates a pending group for cache refresh dedup.
// Exported for use by server.New() during chain assembly.
func NewRefreshGroup() *pending.Group[PendingKey] {
	return pending.NewGroup[PendingKey]()
}

// --- Exported methods ---

// Join checks whether an identical query is already in flight.  If so, it
// blocks until the leader finishes and returns the shared result with
// follower=true.  If not, the caller becomes the leader: it must call Done
// with the result after the upstream query completes, and Join returns
// follower=false.
func (p *PendingRequests) Join(qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, dnssecOK bool) (*resolver.QueryResult, bool) {
	key := BuildPendingKey(qname, qtype, qclass, ecsOpt, dnssecOK)

	p.mu.Lock()
	call, loaded := p.sets[key]
	if !loaded {
		call = &pendingCall{done: make(chan struct{})}
		p.sets[key] = call
		p.mu.Unlock()
		return nil, false // leader
	}
	p.mu.Unlock()

	// Follower: wait for leader to finish.  Safety timeout prevents
	// indefinite blocking if the leader panics and Done is never called.
	log.Debugf("CACHE: pending-request dedup — waiting for in-flight query of %s (type=%s)", qname, dns.TypeToString[qtype])
	// NOTE(L20): 60s follower timeout is not configurable. Ok for most deployments;
	// high-latency upstreams may need a longer timeout.
	timer := time.NewTimer(60 * time.Second)
	select {
	case <-call.done:
		if !timer.Stop() {
			<-timer.C
		}
	case <-timer.C:
		log.Warnf("CACHE: pending-request follower timeout for %s", qname)
		return &resolver.QueryResult{Err: errors.New("pending request timeout")}, true
	}
	return call.result, true
}

// Done stores the result and wakes all waiting followers.  Must only be
// called by the leader (i.e. after Join returned follower=false).
func (p *PendingRequests) Done(qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, dnssecOK bool, result *resolver.QueryResult) {
	key := BuildPendingKey(qname, qtype, qclass, ecsOpt, dnssecOK)

	p.mu.Lock()
	call, ok := p.sets[key]
	if !ok {
		p.mu.Unlock()
		return
	}
	delete(p.sets, key)
	p.mu.Unlock()

	call.result = result
	close(call.done)
}

// --- Unexported helpers ---

// BuildPendingKey constructs a PendingKey from the given parameters.
func BuildPendingKey(qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, dnssecOK bool) PendingKey {
	ecsAddr, ecsPrefix := "", uint8(0)
	if ecsOpt != nil && ecsOpt.Address != nil {
		ecsAddr = ecsOpt.Address.String()
		ecsPrefix = ecsOpt.SourcePrefix
	}
	return PendingKey{
		qname:     qname,
		qtype:     qtype,
		qclass:    qclass,
		ecsAddr:   ecsAddr,
		ecsPrefix: ecsPrefix,
		dnssecOK:  dnssecOK,
	}
}
