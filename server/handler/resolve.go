package handler

import (
	"context"
	"zjdns/cache"
	"zjdns/edns"
	"zjdns/server/resolver"
	"zjdns/server/resolver/dnssec"
)

// Secondary resolves an additional QTYPE for an in-flight query: cache
// first (fresh entries only — stale secondary data would be served with its
// full stored TTL and no stale-answer EDE), then singleflight resolution
// through the shared pending group.  This is the single implementation of
// the lookup pattern the MQTYPE QTx merge and the DNS64 A-lookup share.
type Secondary struct {
	store    cache.Store
	resolver Resolver
	pending  *PendingRequests
}

// NewSecondary creates a Secondary lookup from the shared chain
// collaborators (nil store/pending skip those stages).
func NewSecondary(store cache.Store, res Resolver, pending *PendingRequests) *Secondary {
	return &Secondary{store: store, resolver: res, pending: pending}
}

// Lookup returns the resolution result for qname/qtype, preferring a fresh
// cache entry.  Cached NODATA answers are returned as-is (empty Answer) —
// the caller decides what an empty answer means for its transform.
func (s *Secondary) Lookup(ctx context.Context, qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, dnssecOK bool) *resolver.QueryResult {
	if s.store != nil {
		if entry, found, isExpired := s.store.Get(qname, qtype, qclass, ecsOpt); found {
			if !isExpired && entry.Unpack() == nil {
				return &resolver.QueryResult{
					Answer: entry.Answer, Authority: entry.Authority, Additional: entry.Additional,
					Validated: entry.Validated, Rcode: entry.WireRcode(), Authoritative: entry.WireAuthoritative(),
					Cacheable: true,
				}
			}
			// Every skipped path — expired, or unpack failure — still
			// returns the pooled TTL-offset slice.
			entry.ReleaseOffsets()
		}
	}
	query := func() *resolver.QueryResult {
		return s.resolver.Query(ctx, Question{Name: qname, Qtype: qtype, Qclass: qclass}, ecsOpt)
	}
	if s.pending != nil {
		return s.pending.DoJoin(qname, qtype, qclass, ecsOpt, dnssecOK, query)
	}
	return query()
}

// StoreIfCacheable writes a resolution result to the cache under the single
// cacheability gate: bogus DNSSEC results are never cached (an enforce
// instance sharing the DB must not serve them from cache), and validated
// RRsets get the RFC 4035 §5.3.3 TTL cap.  Returns true when the entry was
// written.  This is the only path that populates the response cache from a
// QueryResult — the miss path, background refreshes and MQTYPE additional
// types all funnel through it.
func StoreIfCacheable(store cache.Store, qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, qr *resolver.QueryResult) bool {
	if !qr.Cacheable || !resolver.DNSSECCacheable(qr.Validated, qr.DNSSECEDE) {
		return false
	}
	// RFC 4035 §5.3.3: cap TTL of authenticated RRsets.
	if qr.Validated {
		dnssec.CapValidatedTTL(qr.Answer, qr.Authority, qr.Additional)
	}
	store.Set(qname, qtype, qclass, ecsOpt, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.Rcode)
	return true
}
