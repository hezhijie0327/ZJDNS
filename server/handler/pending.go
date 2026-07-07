package handler

import (
	"sync"

	"codeberg.org/miekg/dns"

	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/server/resolver"
)

// pendingKey is a pre-computed cache key for deduplicating concurrent identical
// queries.  It mirrors the cache lookup key (qname, qtype, qclass, ecs_addr,
// ecs_prefix, dnssec_ok).
type pendingKey struct {
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

// PendingRequests deduplicates concurrent identical queries.  When multiple
// clients query the same name+type+ECS before the result is cached, only the
// first query (leader) is sent upstream.  Followers block until the leader
// completes, then receive the same result.  This reduces upstream load and
// closes the window for cache-poisoning attacks that exploit concurrent
// identical queries.
type PendingRequests struct {
	mu   sync.Mutex
	sets map[pendingKey]*pendingCall
}

// NewPendingRequests creates a PendingRequests ready for use.
func NewPendingRequests() *PendingRequests {
	return &PendingRequests{
		sets: make(map[pendingKey]*pendingCall),
	}
}

// Join checks whether an identical query is already in flight.  If so, it
// blocks until the leader finishes and returns the shared result with
// follower=true.  If not, the caller becomes the leader: it must call Done
// with the result after the upstream query completes, and Join returns
// follower=false.
func (p *PendingRequests) Join(qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, dnssecOK bool) (*resolver.QueryResult, bool) {
	key := buildPendingKey(qname, qtype, qclass, ecsOpt, dnssecOK)

	p.mu.Lock()
	call, loaded := p.sets[key]
	if !loaded {
		call = &pendingCall{done: make(chan struct{})}
		p.sets[key] = call
		p.mu.Unlock()
		return nil, false // leader
	}
	p.mu.Unlock()

	// Follower: wait for leader to finish.
	log.Debugf("CACHE: pending-request dedup — waiting for in-flight query of %s (type=%s)", qname, dns.TypeToString[qtype])
	<-call.done
	return call.result, true
}

// Done stores the result and wakes all waiting followers.  Must only be
// called by the leader (i.e. after Join returned follower=false).
func (p *PendingRequests) Done(qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, dnssecOK bool, result *resolver.QueryResult) {
	key := buildPendingKey(qname, qtype, qclass, ecsOpt, dnssecOK)

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

// buildPendingKey constructs a pendingKey from the given parameters.
func buildPendingKey(qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, dnssecOK bool) pendingKey {
	ecsAddr, ecsPrefix := "", uint8(0)
	if ecsOpt != nil && ecsOpt.Address != nil {
		ecsAddr = ecsOpt.Address.String()
		ecsPrefix = ecsOpt.SourcePrefix
	}
	return pendingKey{
		qname:     qname,
		qtype:     qtype,
		qclass:    qclass,
		ecsAddr:   ecsAddr,
		ecsPrefix: ecsPrefix,
		dnssecOK:  dnssecOK,
	}
}
