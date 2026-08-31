package resolver

import (
	"context"
	"errors"
	"sync/atomic"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/server/resolver/dnssec"

	"codeberg.org/miekg/dns"
)

// fallbackCoord coordinates the delayed-adoption fallback race for one
// queryUpstream call: primaries and fallbacks launch together at t=0, but a
// fallback result is only served after DefaultFallbackTimeout elapses
// without a usable primary result.  After adoption the primaries keep
// running detached from the client path; the first usable primary result
// fills the cache directly (background fill) and cancels the rest.
type fallbackCoord struct {
	// adopted is set only when a fallback result is actually handed to the
	// client.  Senders re-check it after delivering their result: true means
	// the wait loop already returned, so a late primary result must fill the
	// cache instead of racing for the client.
	adopted atomic.Bool
	// filled elects the single background cache writer among late primaries.
	filled atomic.Bool
	// fallbackResult holds the first stashed fallback result (NOERROR or
	// NXDOMAIN — SERVFAIL is dropped like any upstream SERVFAIL).
	fallbackResult atomic.Pointer[QueryResult]
	// fallbackReady wakes the wait loop when the first fallback result
	// lands (capacity 1 — only the CAS winner signals).
	fallbackReady chan struct{}
	// cancelPrimary ends the detached primary context: on any non-adoption
	// return of queryUpstream, or after the background fill completes.
	cancelPrimary context.CancelCauseFunc

	question Question        // cache key for the background fill
	ecs      *edns.ECSOption // cache key for the background fill
}

// fallbackMarkEDE builds the ZJDNS-private EDE attached to every result
// adopted from a fallback upstream.  Downstream ZJDNS instances refuse to
// cache responses carrying it.
func fallbackMarkEDE() *dns.EDE {
	return &dns.EDE{InfoCode: edns.EDEZJDNSFallback, ExtraText: edns.FallbackEDEText}
}

// stash records the first fallback result and wakes the wait loop.  Later
// fallback results are dropped — the first answer stands.
func (c *fallbackCoord) stash(res *QueryResult) {
	if c.fallbackResult.CompareAndSwap(nil, res) {
		select {
		case c.fallbackReady <- struct{}{}:
		default:
		}
	}
}

// tryAdopt serves a pending primary result if one exists (primaries always
// beat the fallback — drain before adopting), otherwise adopts the stashed
// fallback result.  Returns the result to serve and true when the query is
// done; done=false means the timer fired before any fallback result landed
// and the wait loop must keep going.
func (c *fallbackCoord) tryAdopt(resultChan <-chan QueryResult, nxdomainResult *atomic.Pointer[QueryResult]) (QueryResult, bool) {
	select {
	case res, ok := <-resultChan:
		if ok {
			if errors.Is(res.Err, ErrCIDRFilterRefused) {
				return QueryResult{Err: ErrCIDRFilterRefused}, true
			}
			if res.Server != "" {
				return res, true
			}
		}
	default:
	}
	if nx := nxdomainResult.Load(); nx != nil && nx.Server != "" {
		return *nx, true
	}
	stashed := c.fallbackResult.Load()
	if stashed == nil {
		return QueryResult{}, false
	}
	c.adopted.Store(true)
	log.Debugf("UPSTREAM: no primary result within the fallback timeout — adopting fallback answer")
	return *stashed, true
}

// maybeBackfill runs fill exactly once when a fallback result was already
// adopted: the late primary result bypasses the (already returned) wait loop
// and populates the cache directly.  The re-check-after-deliver ordering
// closes the race with tryAdopt: tryAdopt drains/loads a primary result
// BEFORE setting adopted, so either it served the result (adopted stays
// false, no fill) or it adopted the fallback (this check catches it).
func (c *fallbackCoord) maybeBackfill(fill func()) {
	if c != nil && c.adopted.Load() && c.filled.CompareAndSwap(false, true) {
		fill()
	}
}

// fillCacheFromResult writes a late-arriving primary result to the cache
// after a fallback result was served to the client.  It mirrors the
// CacheStore middleware's gates and preparation (cacheability check,
// canonical-case fold, RFC 4035 §5.3.3 TTL cap).
func (r *Resolver) fillCacheFromResult(coord *fallbackCoord, res *QueryResult) {
	defer coord.cancelPrimary(errors.New("background fill complete"))
	if !res.Cacheable || !DNSSECCacheable(res.Validated, res.DNSSECEDE) {
		return
	}
	zdnsutil.FoldCase(res.Answer)
	zdnsutil.FoldCase(res.Authority)
	zdnsutil.FoldCase(res.Additional)
	if res.Validated {
		dnssec.CapValidatedTTL(res.Answer, res.Authority, res.Additional)
	}
	r.cache.Set(coord.question.Name, coord.question.Qtype, coord.question.Qclass, coord.ecs,
		res.Answer, res.Authority, res.Additional, res.Validated, res.Rcode)
	log.Debugf("UPSTREAM: fallback was served; background-filled cache for %s", coord.question.Name)
}

// DNSSECCacheable reports whether a resolution result may be cached.
// A validated (AD=1) response is always cached — the trust chain has been
// verified and a bogus EDE that leaks through is a stale artifact from an
// earlier delegation level (sticky chain.lastEDECode), not a real failure.
// An unvalidated response carrying a bogus-class EDE (6/7/8/1/12) must
// never be cached: a dnssec_enforce instance reading a shared cache would
// otherwise serve the unauthenticated answer, bypassing the enforce gate.
// RRSIGs-missing keeps the existing insecure treatment and stays cacheable.
// Shared by the CacheStore middleware and the fallback background fill.
func DNSSECCacheable(validated bool, ede uint16) bool {
	if validated {
		return true
	}
	return ede == 0 || ede == dns.ExtendedErrorRRSIGsMissing
}
