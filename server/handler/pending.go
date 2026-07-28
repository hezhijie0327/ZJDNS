package handler

import (
	"fmt"
	"sync"
	"time"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
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
	sets *lrumap.Map[PendingKey, *pendingCall]
}

// --- Types ---

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
	once   sync.Once // guards closing of done channel
}

const pendingRequestCapacity = 10000 // safety bound against unbounded growth

// NewPendingRequests creates a PendingRequests ready for use.
func NewPendingRequests() *PendingRequests {
	p := &PendingRequests{
		sets: lrumap.New[PendingKey, *pendingCall](pendingRequestCapacity),
	}
	p.sets.OnEvict = func(_ PendingKey, call *pendingCall) { call.once.Do(func() { close(call.done) }) }
	return p
}

// NewRefreshGroup creates a pending group for cache refresh deduplication.
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

	call := &pendingCall{done: make(chan struct{})}
	actual, loaded := p.sets.LoadOrStore(key, call)
	if !loaded {
		return nil, false // leader (our call was stored)
	}

	// Follower: wait for leader to finish.  Safety timeout prevents
	// indefinite blocking if the leader panics and Done is never called.
	log.Debugf("CACHE: pending-request dedup — waiting for in-flight query of %s (type=%s)", qname, dns.TypeToString[qtype])
	// NOTE(L20): follower timeout uses config.DefaultPendingFollowerTimeout.
	// Ok for most deployments; high-latency upstreams may need a longer timeout.
	timer := time.NewTimer(config.DefaultPendingFollowerTimeout)
	select {
	case <-actual.done:
		if !timer.Stop() {
			<-timer.C
		}
	case <-timer.C:
		log.Debugf("CACHE: pending-request follower timeout for %s (type=%s)", qname, dns.TypeToString[qtype])
		return &resolver.QueryResult{Err: fmt.Errorf("pending request timeout for %s %s", qname, dns.TypeToString[qtype])}, true
	}
	return actual.result, true
}

// Done stores the result and wakes all waiting followers.  Must only be
// called by the leader (i.e. after Join returned follower=false).
func (p *PendingRequests) Done(qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, dnssecOK bool, result *resolver.QueryResult) {
	key := BuildPendingKey(qname, qtype, qclass, ecsOpt, dnssecOK)

	call, ok := p.sets.Get(key)
	if !ok {
		return
	}
	p.sets.Delete(key)

	// Clone records before sharing with followers to prevent concurrent
	// modification of shared RR headers (e.g. zone rule domain rewrite
	// via restoreDomain).
	call.result = cloneQueryResult(result)
	call.once.Do(func() { close(call.done) })
}

// DoJoin handles the leader/follower pattern for singleflight dedup.  If a
// follower, it returns the shared result from an in-flight query.  If the
// caller is the leader, it executes fn, stores the result via Done, and
// returns the result.
func (p *PendingRequests) DoJoin(qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, dnssecOK bool, fn func() *resolver.QueryResult) *resolver.QueryResult {
	if qr, follower := p.Join(qname, qtype, qclass, ecsOpt, dnssecOK); follower {
		return qr
	}
	result := fn()
	p.Done(qname, qtype, qclass, ecsOpt, dnssecOK, result)
	return result
}

// cloneQueryResult returns a deep copy of qr where the Answer, Authority,
// and Additional slices and their RRs are cloned so the result can be safely
// shared with singleflight followers without racing on RR header fields.
func cloneQueryResult(qr *resolver.QueryResult) *resolver.QueryResult {
	if qr == nil {
		return nil
	}
	cloned := *qr
	cloned.Answer = cloneRRs(qr.Answer)
	cloned.Authority = cloneRRs(qr.Authority)
	cloned.Additional = cloneRRs(qr.Additional)
	return &cloned
}

// cloneRRs returns a deep copy of a slice of RRs. Each RR is cloned via
// its Clone method, which copies the header and record data.
func cloneRRs(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		if rr != nil {
			out[i] = rr.Clone()
		}
	}
	return out
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
