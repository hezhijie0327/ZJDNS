package resolver

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
)

// invocationCounter counts per-address invocations.
type invocationCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

// errFastFailPrimary is the sentinel error used by the fast-fail test's
// dead primary.
var errFastFailPrimary = errors.New("primary fast fail")

func (c *invocationCounter) bump(addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[addr]++
}

func (c *invocationCounter) get(addr string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[addr]
}

// newFallbackTestResolver wires a Resolver for fallback-race tests: the
// scripted fake client, a real cache store (so background fills are
// observable via Get), and a short adoption gate.
func newFallbackTestResolver(t *testing.T, client UpstreamClient) (*Resolver, cache.Store) {
	t.Helper()
	r := newTestResolver(client)
	store := cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	t.Cleanup(func() { _ = store.Close() })
	r.cache = store
	r.fallbackTimeout = 40 * time.Millisecond
	return r, store
}

// nsReplyAAfter answers NOERROR with a single A record after a delay, or
// errors out when the context is canceled first.
func nsReplyAAfter(delay time.Duration, ip string) nsScriptHandler {
	return func(ctx context.Context, msg *dns.Msg) *upstream.Result {
		select {
		case <-time.After(delay):
			res := nsReply(msg, dns.RcodeSuccess)
			res.Response.Answer = []dns.RR{&dns.A{
				Hdr:  dns.Header{Name: msg.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
				Addr: netip.MustParseAddr(ip),
			}}
			return res
		case <-ctx.Done():
			return &upstream.Result{Error: ctx.Err()}
		}
	}
}

// nsReplyNXWithSOAAfter answers NXDOMAIN carrying an SOA in Authority (real
// denials always do — and an empty NXDOMAIN would not be cacheable) after a
// delay, or errors out on context cancel.
func nsReplyNXWithSOAAfter(delay time.Duration) nsScriptHandler {
	return func(ctx context.Context, msg *dns.Msg) *upstream.Result {
		select {
		case <-time.After(delay):
			res := nsReply(msg, dns.RcodeNameError)
			res.Response.Ns = []dns.RR{&dns.SOA{
				Hdr:     dns.Header{Name: msg.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
				Ns:      "ns1.example.com.",
				Mbox:    "hostmaster.example.com.",
				Serial:  1,
				Refresh: 3600,
				Retry:   600,
				Expire:  86400,
				Minttl:  60,
			}}
			return res
		case <-ctx.Done():
			return &upstream.Result{Error: ctx.Err()}
		}
	}
}

func resultHasFallbackEDE(qr *QueryResult) bool {
	return qr.UpstreamEDE != nil && qr.UpstreamEDE.InfoCode == edns.EDEZJDNSFallback
}

// TestQueryUpstream_FastPrimaryNoFallback verifies a healthy primary
// suppresses the fallback entirely: the answer carries no fallback EDE and
// stays cacheable.
func TestQueryUpstream_FastPrimaryNoFallback(t *testing.T) {
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": nsReplyAAfter(10*time.Millisecond, "192.0.2.1"),
		"10.0.0.2:53": nsReplyAAfter(10*time.Millisecond, "192.0.2.2"),
	}}
	r, store := newFallbackTestResolver(t, client)
	r.ConfigureServers([]config.UpstreamServer{
		{Address: "10.0.0.1:53", Protocol: config.ProtoUDP},
		{Address: "10.0.0.2:53", Protocol: config.ProtoUDP, Fallback: true},
	})

	qr := r.Query(t.Context(), Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
	if qr.Err != nil {
		t.Fatalf("unexpected error: %v", qr.Err)
	}
	if resultHasFallbackEDE(qr) {
		t.Fatal("primary result carries the fallback EDE")
	}
	if !qr.Cacheable {
		t.Fatal("primary result is not cacheable")
	}
	if _, found, _ := store.Get("example.com.", dns.TypeA, dns.ClassINET, nil); !found {
		// The middleware caches, not the resolver — here only the backfill
		// path writes.  Absence proves no adoption happened.
		t.Log("cache empty as expected (resolver never caches wins directly)")
	}
}

// TestQueryUpstream_FallbackAdoptedAfterTimeout verifies the delayed
// adoption: the primary misses the gate, the stashed fallback is served
// marked with EDE 65280 and Cacheable=false.
func TestQueryUpstream_FallbackAdoptedAfterTimeout(t *testing.T) {
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": nsReplyAAfter(500*time.Millisecond, "192.0.2.1"),
		"10.0.0.2:53": nsReplyAAfter(10*time.Millisecond, "192.0.2.2"),
	}}
	r, store := newFallbackTestResolver(t, client)
	r.ConfigureServers([]config.UpstreamServer{
		{Address: "10.0.0.1:53", Protocol: config.ProtoUDP},
		{Address: "10.0.0.2:53", Protocol: config.ProtoUDP, Fallback: true},
	})

	start := time.Now()
	qr := r.Query(t.Context(), Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
	elapsed := time.Since(start)

	if qr.Err != nil {
		t.Fatalf("unexpected error: %v", qr.Err)
	}
	if !resultHasFallbackEDE(qr) {
		t.Fatalf("served result lacks the fallback EDE: %+v", qr.UpstreamEDE)
	}
	if qr.Cacheable {
		t.Fatal("fallback result must not be cacheable")
	}
	if len(qr.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(qr.Answer))
	}
	// Served at the gate (~40ms), not when the primary finally answers.
	if elapsed > 300*time.Millisecond {
		t.Fatalf("fallback adoption took %v, want ~40ms", elapsed)
	}
	// The fallback result itself never reaches the cache.
	if _, found, _ := store.Get("example.com.", dns.TypeA, dns.ClassINET, nil); found {
		t.Fatal("fallback result was cached")
	}
}

// TestQueryUpstream_BackgroundFillAfterAdoption verifies the late primary
// result fills the cache in the background after the fallback was served,
// and the remaining primary queries are then canceled.
func TestQueryUpstream_BackgroundFillAfterAdoption(t *testing.T) {
	stragglerCanceled := &atomicBool{ch: make(chan struct{}, 1)}
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": nsReplyAAfter(120*time.Millisecond, "192.0.2.1"),
		"10.0.0.2:53": nsReplyAAfter(10*time.Millisecond, "192.0.2.2"),
		"10.0.0.3:53": func(ctx context.Context, msg *dns.Msg) *upstream.Result {
			select {
			case <-ctx.Done():
				stragglerCanceled.set()
				return &upstream.Result{Error: ctx.Err()}
			case <-time.After(5 * time.Second):
				return nsReply(msg, dns.RcodeSuccess)
			}
		},
	}}
	r, store := newFallbackTestResolver(t, client)
	r.ConfigureServers([]config.UpstreamServer{
		{Address: "10.0.0.1:53", Protocol: config.ProtoUDP},
		{Address: "10.0.0.3:53", Protocol: config.ProtoUDP},
		{Address: "10.0.0.2:53", Protocol: config.ProtoUDP, Fallback: true},
	})

	qr := r.Query(t.Context(), Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
	if qr.Err != nil || !resultHasFallbackEDE(qr) {
		t.Fatalf("want fallback-served result, got %+v", qr)
	}

	// The late primary (120ms) backfills the cache after adoption.  Entries
	// are stored pre-packed — presence of the wire proves the fill ran.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if entry, found, _ := store.Get("example.com.", dns.TypeA, dns.ClassINET, nil); found {
			if len(entry.ResponseWire) == 0 {
				t.Fatal("backfilled entry has no stored wire")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background fill never populated the cache")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The fill cancels the remaining primaries — the 5s straggler aborts.
	if !stragglerCanceled.await(3 * time.Second) {
		t.Fatal("straggler was not canceled after the background fill")
	}
}

// TestQueryUpstream_BackgroundFillNXDOMAIN verifies a late primary NXDOMAIN
// fills the negative cache after the fallback was served.
func TestQueryUpstream_BackgroundFillNXDOMAIN(t *testing.T) {
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": nsReplyNXWithSOAAfter(120 * time.Millisecond),
		"10.0.0.2:53": nsReplyAAfter(10*time.Millisecond, "192.0.2.2"),
	}}
	r, store := newFallbackTestResolver(t, client)
	r.ConfigureServers([]config.UpstreamServer{
		{Address: "10.0.0.1:53", Protocol: config.ProtoUDP},
		{Address: "10.0.0.2:53", Protocol: config.ProtoUDP, Fallback: true},
	})

	qr := r.Query(t.Context(), Question{Name: "nonexistent.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
	if qr.Err != nil || !resultHasFallbackEDE(qr) {
		t.Fatalf("want fallback-served result, got %+v", qr)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, found, _ := store.Get("nonexistent.example.com.", dns.TypeA, dns.ClassINET, nil); found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background fill never populated the negative cache")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestQueryUpstream_PrimaryBeatsStashedFallback verifies the drain-before-
// adopt ordering: the fallback is stashed early, but a primary answer
// landing inside the gate always wins (the wait loop serves it directly,
// and even if the timer case wakes first, tryAdopt drains the pending
// primary before adopting).
func TestQueryUpstream_PrimaryBeatsStashedFallback(t *testing.T) {
	for range 20 {
		client := &fakeNSClient{handlers: map[string]nsScriptHandler{
			// Primary lands just inside the 40ms gate — the tight window.
			"10.0.0.1:53": nsReplyAAfter(35*time.Millisecond, "192.0.2.1"),
			"10.0.0.2:53": nsReplyAAfter(5*time.Millisecond, "192.0.2.2"),
		}}
		r, _ := newFallbackTestResolver(t, client)
		r.ConfigureServers([]config.UpstreamServer{
			{Address: "10.0.0.1:53", Protocol: config.ProtoUDP},
			{Address: "10.0.0.2:53", Protocol: config.ProtoUDP, Fallback: true},
		})

		qr := r.Query(t.Context(), Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
		if qr.Err != nil {
			t.Fatalf("unexpected error: %v", qr.Err)
		}
		if resultHasFallbackEDE(qr) {
			// The fallback answered at 5ms and was stashed; the primary at
			// ~35ms must still win — it landed inside the gate.
			t.Fatal("fallback was adopted although the primary answered inside the gate")
		}
	}
}

// TestQueryUpstream_FallbackNXDOMAINAdopted verifies a fallback NXDOMAIN is
// adopted after the gate like a fallback NOERROR (marked, uncacheable).
func TestQueryUpstream_FallbackNXDOMAINAdopted(t *testing.T) {
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": nsReplyAfter(500*time.Millisecond, dns.RcodeSuccess),
		"10.0.0.2:53": nsReplyAfter(10*time.Millisecond, dns.RcodeNameError),
	}}
	r, _ := newFallbackTestResolver(t, client)
	r.ConfigureServers([]config.UpstreamServer{
		{Address: "10.0.0.1:53", Protocol: config.ProtoUDP},
		{Address: "10.0.0.2:53", Protocol: config.ProtoUDP, Fallback: true},
	})

	qr := r.Query(t.Context(), Question{Name: "nonexistent.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
	if qr.Err != nil {
		t.Fatalf("unexpected error: %v", qr.Err)
	}
	if qr.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[qr.Rcode])
	}
	if !resultHasFallbackEDE(qr) || qr.Cacheable {
		t.Fatalf("fallback NXDOMAIN must carry EDE %d and be uncacheable: %+v", edns.EDEZJDNSFallback, qr)
	}
}

// TestQueryUpstream_CascadedFallbackEDENotCached verifies the client side:
// a response carrying the ZJDNS fallback EDE (from a cascaded instance) is
// adopted normally but marked uncacheable.
func TestQueryUpstream_CascadedFallbackEDENotCached(t *testing.T) {
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": func(ctx context.Context, msg *dns.Msg) *upstream.Result {
			res := nsReply(msg, dns.RcodeSuccess)
			res.Response.Answer = []dns.RR{&dns.A{
				Hdr:  dns.Header{Name: msg.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
				Addr: netip.MustParseAddr("192.0.2.1"),
			}}
			res.Response.Pseudo = append(res.Response.Pseudo, &dns.EDE{
				InfoCode:  edns.EDEZJDNSFallback,
				ExtraText: edns.FallbackEDEText,
			})
			return res
		},
	}}
	r := newTestResolver(client)
	r.ConfigureServers([]config.UpstreamServer{
		{Address: "10.0.0.1:53", Protocol: config.ProtoUDP},
	})

	qr := r.Query(t.Context(), Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
	if qr.Err != nil {
		t.Fatalf("unexpected error: %v", qr.Err)
	}
	if qr.Cacheable {
		t.Fatal("cascaded fallback-marked response must not be cacheable")
	}
	if !resultHasFallbackEDE(qr) {
		t.Fatal("fallback EDE must pass through to the client")
	}
	if len(qr.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1 (adoption unaffected)", len(qr.Answer))
	}
}

// TestQueryUpstream_NoFallbackConfiguredUnchanged is the regression guard:
// without any fallback upstream the fan-out behaves exactly as before
// (first-wins, no timers, no stashes).
func TestQueryUpstream_NoFallbackConfiguredUnchanged(t *testing.T) {
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": nsReplyAAfter(10*time.Millisecond, "192.0.2.1"),
		"10.0.0.2:53": nsReplyAAfter(500*time.Millisecond, "192.0.2.2"),
	}}
	r, _ := newFallbackTestResolver(t, client)
	r.ConfigureServers([]config.UpstreamServer{
		{Address: "10.0.0.1:53", Protocol: config.ProtoUDP},
		{Address: "10.0.0.2:53", Protocol: config.ProtoUDP},
	})

	start := time.Now()
	qr := r.Query(t.Context(), Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
	if qr.Err != nil {
		t.Fatalf("unexpected error: %v", qr.Err)
	}
	if resultHasFallbackEDE(qr) || !qr.Cacheable {
		t.Fatalf("plain fan-out result corrupted: %+v", qr)
	}
	if time.Since(start) > 250*time.Millisecond {
		t.Fatal("first-wins waited for the slow upstream")
	}
}

// TestQueryUpstream_FallbackAlwaysQueried documents the eager-launch
// semantics: the fallback is queried at t=0 even when the primary wins
// (delayed adoption, not deferred launching).
func TestQueryUpstream_FallbackAlwaysQueried(t *testing.T) {
	counter := &invocationCounter{counts: map[string]int{}}
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": func(ctx context.Context, msg *dns.Msg) *upstream.Result {
			counter.bump("10.0.0.1:53")
			return nsReplyAfter(10*time.Millisecond, dns.RcodeSuccess)(ctx, msg)
		},
		"10.0.0.2:53": func(ctx context.Context, msg *dns.Msg) *upstream.Result {
			counter.bump("10.0.0.2:53")
			return nsReplyAfter(10*time.Millisecond, dns.RcodeSuccess)(ctx, msg)
		},
	}}
	r, _ := newFallbackTestResolver(t, client)
	r.ConfigureServers([]config.UpstreamServer{
		{Address: "10.0.0.1:53", Protocol: config.ProtoUDP},
		{Address: "10.0.0.2:53", Protocol: config.ProtoUDP, Fallback: true},
	})

	qr := r.Query(t.Context(), Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
	if qr.Err != nil {
		t.Fatalf("unexpected error: %v", qr.Err)
	}
	if counter.get("10.0.0.2:53") != 1 {
		t.Fatalf("fallback queried %d times, want 1 (eager launch)", counter.get("10.0.0.2:53"))
	}
}

// TestQueryUpstream_FastFailPrimaryEarlyAdoption verifies the early-adoption
// path: a primary that fails immediately (dead upstream) plus a fast fallback
// must NOT idle out the full fallback timeout — once every primary has exited,
// the stashed fallback answer is adopted on arrival.
func TestQueryUpstream_FastFailPrimaryEarlyAdoption(t *testing.T) {
	for range 10 {
		client := &fakeNSClient{handlers: map[string]nsScriptHandler{
			// Primary errors out instantly (dead upstream).
			"10.0.0.1:53": func(context.Context, *dns.Msg) *upstream.Result {
				return &upstream.Result{Error: errFastFailPrimary}
			},
			// Fallback answers at 15ms — far inside the 1s gate below.
			"10.0.0.2:53": nsReplyAAfter(15*time.Millisecond, "192.0.2.2"),
		}}
		r, _ := newFallbackTestResolver(t, client)
		r.fallbackTimeout = time.Second
		r.ConfigureServers([]config.UpstreamServer{
			{Address: "10.0.0.1:53", Protocol: config.ProtoUDP},
			{Address: "10.0.0.2:53", Protocol: config.ProtoUDP, Fallback: true},
		})

		start := time.Now()
		qr := r.Query(t.Context(), Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
		elapsed := time.Since(start)
		if qr.Err != nil {
			t.Fatalf("unexpected error: %v", qr.Err)
		}
		if !resultHasFallbackEDE(qr) {
			t.Fatal("fallback answer was not adopted")
		}
		// Without early adoption this waits out the 1s gate; the fast path
		// must return shortly after the fallback answer lands.
		if elapsed > 500*time.Millisecond {
			t.Fatalf("adoption took %v — primary fast-fail did not bypass the fallback gate", elapsed)
		}
	}
}

// TestQueryUpstream_MQTypeServfailRetry verifies the forwarding path's
// RFC 10029 fallback: an upstream that SERVFAILs MQTYPE-Query queries is
// retried once without the option (mirroring the recursive walk) — both
// upstreams failing the optioned query previously surfaced SERVFAIL to the
// client for otherwise-resolvable names.
func TestQueryUpstream_MQTypeServfailRetry(t *testing.T) {
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": func(ctx context.Context, msg *dns.Msg) *upstream.Result {
			if hasMQQUERY(msg.Pseudo) {
				return nsReply(msg, dns.RcodeServerFailure)
			}
			res := nsReply(msg, dns.RcodeSuccess)
			res.Response.Answer = []dns.RR{&dns.A{
				Hdr:  dns.Header{Name: msg.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
				Addr: netip.MustParseAddr("192.0.2.9"),
			}}
			return res
		},
	}}
	r := newTestResolver(client)
	r.cache = cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	t.Cleanup(func() { _ = r.cache.Close() })
	r.ConfigureServers([]config.UpstreamServer{
		{Address: "10.0.0.1:53", Protocol: config.ProtoUDP, MQType: []uint16{dns.TypeA, dns.TypeAAAA}},
	})

	qr := r.Query(t.Context(), Question{Name: "mqtest.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
	if qr.Err != nil {
		t.Fatalf("unexpected error: %v", qr.Err)
	}
	if len(qr.Answer) == 0 {
		t.Fatal("optionless retry did not run — SERVFAIL propagated")
	}
}
