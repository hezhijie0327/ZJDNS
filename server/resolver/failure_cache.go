// RFC 9520 negative caching of DNS resolution failures: a bounded in-memory
// LRU keyed by (qname, qtype, qclass) that short-circuits repeated queries
// for names that just failed to resolve.
//
// RFC 9520 §3.2: resolvers MUST implement a cache for resolution failures —
// when an incoming query matches a cached failure, no corresponding outgoing
// queries are sent until the entry expires (the short-circuit here returns
// before the walk / upstream race starts).  Entries live between the 1s
// minimum and the 5-minute cap, with exponential TTL growth for persistent
// failures (§3.2 backoff SHOULD).  DNSSEC validation failures are cached like
// any other failure (§3.4); the DNSSEC EDE code rides along and surfaces via
// the middleware's RFC 8914 response path.
//
// Scope: only ECS-less queries are cached and served — the same qname under
// a different ECS may resolve where another failed, and ECS-carrying queries
// are a minority.  Resource-exhaustion bound (§5): fixed LRU capacity.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// failureKey identifies one failed resolution.  The name is stored
// canonicalized so case-variant queries share the entry.
type failureKey struct {
	qname  string
	qtype  uint16
	qclass uint16
}

// failureEntry is one cached resolution failure.  ttl grows exponentially
// with attempt while the failure persists; ede carries the DNSSEC EDE code
// (0 when the failure was not a DNSSEC validation failure).
type failureEntry struct {
	ts      int64 // log.NowUnix() at record time
	ttl     int   // seconds
	ede     uint16
	attempt int // backoff step — grown on each re-failure after expiry
}

// ErrCachedResolutionFailure marks a SERVFAIL served from the RFC 9520
// failure cache (wrapped with the question for the log path).
var ErrCachedResolutionFailure = errors.New("cached resolution failure")

// fresh reports whether the entry has not yet expired (lazy expiry on read).
func (e *failureEntry) fresh() bool {
	return e.ts+int64(e.ttl) > log.NowUnix()
}

// newFailureLRU builds the bounded failure LRU (RFC 9520 §5: fixed capacity
// bounds the memory devoted to failure caching).
func newFailureLRU() *lrumap.Map[failureKey, *failureEntry] {
	return lrumap.New[failureKey, *failureEntry](config.DefaultResolutionFailureCache)
}

// lookupCachedFailure returns a QueryResult for a still-fresh cached failure
// of this question, or nil on miss.  The result carries the sentinel error so
// the middleware's error path serves SERVFAIL with the recorded DNSSEC EDE.
func (r *Resolver) lookupCachedFailure(question Question) *QueryResult {
	if r.failures == nil {
		return nil
	}
	e, ok := r.failures.Get(failureKey{
		qname:  dnsutil.Canonical(dnsutil.Fqdn(question.Name)),
		qtype:  question.Qtype,
		qclass: question.Qclass,
	})
	if !ok || !e.fresh() {
		return nil
	}
	if log.IsDebug() {
		log.Debugf("RESOLVER: RFC 9520 cached failure hit for %s %s (ttl_remaining=%ds, ede=%d)",
			question.Name, dns.TypeToString[question.Qtype], e.ts+int64(e.ttl)-log.NowUnix(), e.ede)
	}
	return &QueryResult{
		Cacheable: true,
		Err: fmt.Errorf("%w: %s %s", ErrCachedResolutionFailure,
			question.Name, dns.TypeToString[question.Qtype]),
		DNSSECEDE: e.ede,
	}
}

// recordFailure stores a resolution failure with exponential TTL growth:
// 5s on the first failure, doubled per repeated failure of the same
// question, capped at DefaultResolutionFailureMaxTTL (RFC 9520 §3.2).
// Client-side cancellations and policy refusals are not failures of the
// resolution itself and are never recorded.
func (r *Resolver) recordFailure(question Question, qr *QueryResult) {
	if r.failures == nil {
		return
	}
	if errors.Is(qr.Err, ErrCachedResolutionFailure) ||
		errors.Is(qr.Err, ErrCIDRFilterRefused) ||
		errors.Is(qr.Err, context.Canceled) ||
		errors.Is(qr.Err, context.DeadlineExceeded) {
		return
	}

	key := failureKey{
		qname:  dnsutil.Canonical(dnsutil.Fqdn(question.Name)),
		qtype:  question.Qtype,
		qclass: question.Qclass,
	}
	attempt := 0
	if prev, ok := r.failures.Get(key); ok {
		attempt = min(prev.attempt+1, config.DefaultResolutionFailureMaxStep)
	}
	ttl := min(config.DefaultResolutionFailureTTL<<attempt, config.DefaultResolutionFailureMaxTTL)
	r.failures.Set(key, &failureEntry{
		ts:      log.NowUnix(),
		ttl:     int(ttl.Seconds()),
		ede:     qr.DNSSECEDE,
		attempt: attempt,
	})
	if log.IsDebug() {
		log.Debugf("RESOLVER: RFC 9520 caching failure for %s %s (ttl=%ds, attempt=%d, ede=%d)",
			question.Name, dns.TypeToString[question.Qtype], int(ttl.Seconds()), attempt, qr.DNSSECEDE)
	}
}
