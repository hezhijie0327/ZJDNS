package resolver

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
)

// countingErrClient fails every query and counts the calls — the RFC 9520
// short-circuit is verified by a stalled call counter after a cached failure.
type countingErrClient struct {
	calls atomic.Int64
}

func (c *countingErrClient) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) *upstream.Result {
	c.calls.Add(1)
	return &upstream.Result{Error: errors.New("upstream down")}
}

// newFailureCacheResolver wires a Resolver whose upstream always fails, with
// a real cache store (New() requires one) and a live failure LRU.
func newFailureCacheResolver(t *testing.T, client UpstreamClient) *Resolver {
	t.Helper()
	r := newTestResolver(client)
	store := cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	t.Cleanup(func() { _ = store.Close() })
	r.cache = store
	r.failures = newFailureLRU()
	return r
}

// TestFailureCache_ShortCircuitsUpstream verifies the RFC 9520 §3.2 core
// requirement: while a failure entry is fresh, no corresponding outgoing
// query is issued at all.
func TestFailureCache_ShortCircuitsUpstream(t *testing.T) {
	client := &countingErrClient{}
	r := newFailureCacheResolver(t, client)
	r.ConfigureServers([]config.UpstreamServer{{Address: "10.0.0.1:53", Protocol: config.ProtoUDP}})
	q := Question{Name: "dead.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	for range 3 {
		qr := r.Query(t.Context(), q, nil)
		if qr.Err == nil {
			t.Fatal("expected failure result")
		}
	}
	if got := client.calls.Load(); got != 1 {
		t.Fatalf("upstream called %d times, want 1 (RFC 9520: no outgoing query on cached failure)", got)
	}
	// Case-variant queries share the canonicalized entry.
	qr := r.Query(t.Context(), Question{Name: "DEAD.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
	if !errors.Is(qr.Err, ErrCachedResolutionFailure) {
		t.Fatalf("case-variant query not served from cache: %v", qr.Err)
	}
	if got := client.calls.Load(); got != 1 {
		t.Fatalf("upstream called %d times after case-variant hit, want 1", got)
	}
}

// TestFailureCache_BackoffAndCap verifies the exponential TTL growth on
// repeated failures and the RFC 9520 5-minute hard cap.
func TestFailureCache_BackoffAndCap(t *testing.T) {
	r := newFailureCacheResolver(t, &countingErrClient{})
	q := Question{Name: "flaky.example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	key := failureKey{qname: q.Name, qtype: q.Qtype, qclass: q.Qclass}

	wantTTLs := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second}
	for i, want := range wantTTLs {
		if e, ok := r.failures.Get(key); ok {
			e.ts -= int64(e.ttl) // force-expire so the re-failure grows the backoff
		}
		r.recordFailure(q, &QueryResult{Err: errors.New("upstream down")})
		e, ok := r.failures.Get(key)
		if !ok {
			t.Fatalf("step %d: no failure entry recorded", i)
		}
		if got := time.Duration(e.ttl) * time.Second; got != want {
			t.Fatalf("step %d: ttl=%v, want %v", i, got, want)
		}
	}
	// Walk the backoff to the shift cap — the entry TTL must clamp at 5min.
	for range 10 {
		if e, ok := r.failures.Get(key); ok {
			e.ts -= int64(e.ttl)
		}
		r.recordFailure(q, &QueryResult{Err: errors.New("upstream down")})
	}
	e, _ := r.failures.Get(key)
	if got := time.Duration(e.ttl) * time.Second; got != config.DefaultResolutionFailureMaxTTL {
		t.Fatalf("capped ttl=%v, want %v", got, config.DefaultResolutionFailureMaxTTL)
	}
}

// TestFailureCache_ExpiryRequeries verifies that an expired entry lets the
// resolver query upstream again (the cache never outlives its TTL).
func TestFailureCache_ExpiryRequeries(t *testing.T) {
	client := &countingErrClient{}
	r := newFailureCacheResolver(t, client)
	r.ConfigureServers([]config.UpstreamServer{{Address: "10.0.0.1:53", Protocol: config.ProtoUDP}})
	q := Question{Name: "recovering.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	if qr := r.Query(t.Context(), q, nil); qr.Err == nil {
		t.Fatal("expected failure")
	}
	if qr := r.Query(t.Context(), q, nil); !errors.Is(qr.Err, ErrCachedResolutionFailure) {
		t.Fatalf("expected cached failure, got %v", qr.Err)
	}
	// Force-expire: the next query must reach the upstream again.
	e, ok := r.failures.Get(failureKey{qname: q.Name, qtype: q.Qtype, qclass: q.Qclass})
	if !ok {
		t.Fatal("no entry")
	}
	e.ts -= int64(e.ttl)
	if qr := r.Query(t.Context(), q, nil); errors.Is(qr.Err, ErrCachedResolutionFailure) {
		t.Fatal("expired entry still short-circuiting")
	}
	if got := client.calls.Load(); got != 2 {
		t.Fatalf("upstream called %d times, want 2 after expiry", got)
	}
}

// TestFailureCache_NonFailureErrorsNotRecorded verifies that policy refusals
// and client-side cancellations do not poison the cache.
func TestFailureCache_NonFailureErrorsNotRecorded(t *testing.T) {
	r := newFailureCacheResolver(t, &countingErrClient{})
	q := Question{Name: "policy.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	r.recordFailure(q, &QueryResult{Err: ErrCIDRFilterRefused})
	r.recordFailure(q, &QueryResult{Err: context.Canceled})
	r.recordFailure(q, &QueryResult{Err: context.DeadlineExceeded})
	if _, ok := r.failures.Get(failureKey{qname: q.Name, qtype: q.Qtype, qclass: q.Qclass}); ok {
		t.Fatal("policy/cancellation errors must not be recorded")
	}
}

// TestFailureCache_ECSQueriesBypass verifies that ECS-carrying queries neither
// serve cached failures nor record their own.
func TestFailureCache_ECSQueriesBypass(t *testing.T) {
	client := &countingErrClient{}
	r := newFailureCacheResolver(t, client)
	r.ConfigureServers([]config.UpstreamServer{{Address: "10.0.0.1:53", Protocol: config.ProtoUDP}})
	q := Question{Name: "geo.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	ecs := &edns.ECSOption{Family: 1, SourcePrefix: 24, Address: []byte{192, 0, 2, 0}}

	if qr := r.Query(t.Context(), q, ecs); qr.Err == nil || errors.Is(qr.Err, ErrCachedResolutionFailure) {
		t.Fatalf("expected uncached failure, got %v", qr.Err)
	}
	if _, ok := r.failures.Get(failureKey{qname: q.Name, qtype: q.Qtype, qclass: q.Qclass}); ok {
		t.Fatal("ECS query failure must not be recorded")
	}
	// Seed a failure via an ECS-less query, then confirm the ECS query
	// still reaches upstream.
	r.recordFailure(q, &QueryResult{Err: errors.New("zone down"), DNSSECEDE: dns.ExtendedErrorDNSBogus})
	before := client.calls.Load()
	if qr := r.Query(t.Context(), q, ecs); qr == nil || errors.Is(qr.Err, ErrCachedResolutionFailure) {
		t.Fatal("ECS query must bypass the failure cache")
	}
	if client.calls.Load() != before+1 {
		t.Fatal("ECS query was short-circuited by the failure cache")
	}
}

// TestFailureCache_EDECarried verifies that the recorded DNSSEC EDE code
// surfaces on the cached-failure result (RFC 9520 §3.4 + RFC 8914).
func TestFailureCache_EDECarried(t *testing.T) {
	r := newFailureCacheResolver(t, &countingErrClient{})
	q := Question{Name: "bogus.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	r.recordFailure(q, &QueryResult{Err: errors.New("DNSSEC bogus"), DNSSECEDE: dns.ExtendedErrorDNSBogus})

	qr := r.lookupCachedFailure(q)
	if qr == nil {
		t.Fatal("expected cached failure")
	}
	if qr.DNSSECEDE != dns.ExtendedErrorDNSBogus {
		t.Fatalf("DNSSECEDE=%d, want %d", qr.DNSSECEDE, dns.ExtendedErrorDNSBogus)
	}
}

// TestFailureCache_LRUBound verifies the capacity bound (RFC 9520 §5
// resource-exhaustion mitigation).
func TestFailureCache_LRUBound(t *testing.T) {
	r := newFailureCacheResolver(t, &countingErrClient{})
	for i := range config.DefaultResolutionFailureCache + 64 {
		q := Question{Name: "q" + strconv.Itoa(i) + ".example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		r.recordFailure(q, &QueryResult{Err: errors.New("down")})
	}
	if r.failures.Len() > config.DefaultResolutionFailureCache {
		t.Fatalf("failure cache grew to %d, cap is %d", r.failures.Len(), config.DefaultResolutionFailureCache)
	}
}
