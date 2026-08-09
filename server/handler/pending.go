package handler

import (
	"errors"
	"fmt"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
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
	cg *pending.CallGroup[PendingKey, *resolver.QueryResult]
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

const pendingRequestCapacity = 10000 // safety bound against unbounded growth

// errPendingEvicted is delivered to followers when their in-flight leader
// call is LRU-evicted before completion — the query must surface as SERVFAIL
// rather than being silently dropped (R3-M4).
var errPendingEvicted = errors.New("pending request evicted before completion")

// NewPendingRequests creates a PendingRequests ready for use.
func NewPendingRequests() *PendingRequests {
	return &PendingRequests{
		cg: pending.NewCallGroup[PendingKey, *resolver.QueryResult](
			pendingRequestCapacity,
			config.DefaultPendingFollowerTimeout,
			cloneQueryResult,
		),
	}
}

// NewRefreshGroup creates a pending group for cache refresh deduplication.
func NewRefreshGroup() *pending.Group[PendingKey] {
	return pending.NewGroup[PendingKey]()
}

// --- Exported methods ---

// Join checks whether an identical query is already in flight.  If so, it
// blocks until the leader finishes and returns the shared result with
// follower=true.  If not, the caller becomes the leader: Join returns
// (token, nil, false) and the leader must call Done with that same token
// after the upstream query completes.
func (p *PendingRequests) Join(qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, dnssecOK bool) (pending.Token[PendingKey, *resolver.QueryResult], *resolver.QueryResult, bool) {
	key := BuildPendingKey(qname, qtype, qclass, ecsOpt, dnssecOK)

	tok, qr, err, follower := p.cg.Join(key)
	if !follower {
		return tok, nil, false // leader
	}

	if errors.Is(err, pending.ErrTimeout) {
		log.Debugf("CACHE: pending-request follower timeout for %s (type=%s)", qname, dns.TypeToString[qtype])
		return pending.Token[PendingKey, *resolver.QueryResult]{}, &resolver.QueryResult{Err: fmt.Errorf("pending request timeout for %s %s", qname, dns.TypeToString[qtype])}, true
	}
	if errors.Is(err, pending.ErrEvicted) {
		return pending.Token[PendingKey, *resolver.QueryResult]{}, &resolver.QueryResult{Err: errPendingEvicted}, true
	}
	// Normal follower: leader completed and shared the result.
	if qr == nil {
		return pending.Token[PendingKey, *resolver.QueryResult]{}, &resolver.QueryResult{Err: errors.New("pending request returned nil result")}, true
	}
	return pending.Token[PendingKey, *resolver.QueryResult]{}, qr, true
}

// Done stores the result and wakes all waiting followers under the leader
// token from Join (M6 — publishing by key would let an evicted leader's
// result land in a replacement entry).
func (p *PendingRequests) Done(tok pending.Token[PendingKey, *resolver.QueryResult], result *resolver.QueryResult) {
	p.cg.Done(tok, result, nil)
}

// DoJoin handles the leader/follower pattern for singleflight dedup.  If a
// follower, it returns the shared result from an in-flight query.  If the
// caller is the leader, it executes fn, stores the result, and returns it.
func (p *PendingRequests) DoJoin(qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, dnssecOK bool, fn func() *resolver.QueryResult) *resolver.QueryResult {
	tok, qr, follower := p.Join(qname, qtype, qclass, ecsOpt, dnssecOK)
	if follower {
		return qr
	}
	result := fn()
	p.Done(tok, result)
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
	cloned.Answer = zdnsutil.CloneRRs(qr.Answer)
	cloned.Authority = zdnsutil.CloneRRs(qr.Authority)
	cloned.Additional = zdnsutil.CloneRRs(qr.Additional)
	return &cloned
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
